//! Windows SCM integration.
//!
//! The service runs as LocalSystem in production.  It reports start/running/
//! stop states, accepts Stop and Shutdown, and cancels the same token that
//! `run` uses on SIGTERM in console mode.  There is no GUI in this process.
//!
//! Installation is deliberately not implemented here; M5's MSI registers the
//! service with `--service` in its image path.

use std::ffi::OsString;
use std::process;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::{define_windows_service, Result as ServiceResult};

use crate::{build_config, init_service_log, parse_args, run};

pub const SERVICE_NAME: &str = "rustvpn-clientd";

define_windows_service!(ffi_service_main, service_main);

/// Start the SCM dispatcher.  Blocks until the service stops.
pub fn run_dispatcher() -> ServiceResult<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(_arguments: Vec<OsString>) {
    init_service_log();
    let args = parse_args();
    let mut config = match build_config(&args, false) {
        Ok(config) => config,
        Err(error) => {
            dlog!("service configuration error: {error:#}");
            process::exit(1);
        }
    };
    crate::harden_process_identity(&config);
    let (ready_tx, mut ready_rx) = tokio::sync::oneshot::channel();
    config.ready = Some(ready_tx);

    let shutdown = CancellationToken::new();
    let handler_shutdown = shutdown.clone();
    let status = match service_control_handler::register(SERVICE_NAME, move |control| {
        match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                // Cancelling is the only action needed: `run` performs the
                // engine shutdown, listener close and clean marker handling,
                // exactly like the console SIGTERM path.
                handler_shutdown.cancel();
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    }) {
        Ok(status) => status,
        Err(error) => {
            dlog!("cannot register the service control handler: {error}");
            process::exit(1);
        }
    };

    if let Err(error) = status.set_service_status(service_status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::NO_ERROR,
        1,
    )) {
        dlog!("cannot report StartPending: {error}");
        process::exit(1);
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            dlog!("cannot create the service runtime: {error}");
            let _ = status.set_service_status(service_status(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                ServiceExitCode::ServiceSpecific(1),
                0,
            ));
            process::exit(1);
        }
    };

    let result = runtime.block_on(async {
        let mut run_future = Box::pin(run(config, shutdown));
        tokio::select! {
            result = &mut run_future => result,
            ready = &mut ready_rx => {
                if ready.is_ok() {
                    if let Err(error) = status.set_service_status(service_status(
                        ServiceState::Running,
                        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                        ServiceExitCode::NO_ERROR,
                        0,
                    )) {
                        dlog!("cannot report Running: {error}");
                    }
                }
                run_future.await
            }
        }
    });
    let failed = result.is_err();
    if let Err(error) = result {
        dlog!("service stopped with an error: {error:#}");
    }
    let exit = if failed {
        ServiceExitCode::ServiceSpecific(1)
    } else {
        ServiceExitCode::NO_ERROR
    };
    if let Err(error) = status.set_service_status(service_status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit,
        0,
    )) {
        dlog!("cannot report Stopped: {error}");
    }
    if failed {
        // SCM records the process exit code; a failed start/stop is visible in
        // the Event Log and to the failure-recovery policy installed in M5.
        process::exit(1);
    }
}

fn service_status(
    state: ServiceState,
    accepted: ServiceControlAccept,
    exit_code: ServiceExitCode,
    checkpoint: u32,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accepted,
        exit_code,
        checkpoint,
        wait_hint: Duration::from_secs(30),
        process_id: None,
    }
}
