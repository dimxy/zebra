//! Fixed test vectors for the RPC server.

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use futures::FutureExt;
use tower::buffer::Buffer;

use zebra_chain::{chain_tip::NoChainTip, parameters::Network::*};
use zebra_node_services::BoxError;

use zebra_test::mock_service::MockService;

use super::super::*;

/// Test that the JSON-RPC server spawns when configured with a single thread.
#[test]
fn rpc_server_spawn_single_thread() {
    rpc_server_spawn(false)
}

/// Test that the JSON-RPC server spawns when configured with multiple threads.
#[test]
fn rpc_sever_spawn_parallel_threads() {
    rpc_server_spawn(true)
}

/// Test if the RPC server will spawn on a randomly generated port.
///
/// Set `parallel_cpu_threads` to true to auto-configure based on the number of CPU cores.
#[tracing::instrument]
fn rpc_server_spawn(parallel_cpu_threads: bool) {
    let _init_guard = zebra_test::init();

    let port = zebra_test::net::random_known_port();
    let config = Config {
        listen_addr: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into()),
        parallel_cpu_threads: if parallel_cpu_threads { 2 } else { 1 },
    };

    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        let mut mempool: MockService<_, _, _, BoxError> = MockService::build().for_unit_tests();
        let mut state: MockService<_, _, _, BoxError> = MockService::build().for_unit_tests();

        info!("spawning RPC server...");

        let (rpc_server_task_handle, rpc_tx_queue_task_handle) = RpcServer::spawn(
            config,
            "RPC server test",
            Buffer::new(mempool.clone(), 1),
            Buffer::new(state.clone(), 1),
            NoChainTip,
            Mainnet,
        );

        info!("spawned RPC server, checking services...");

        mempool.expect_no_requests().await;
        state.expect_no_requests().await;

        // The server and queue tasks should continue without errors or panics
        let rpc_server_task_result = rpc_server_task_handle.now_or_never();
        assert!(matches!(rpc_server_task_result, None));

        let rpc_tx_queue_task_result = rpc_tx_queue_task_handle.now_or_never();
        assert!(matches!(rpc_tx_queue_task_result, None));

        // TODO: when we return server.close_handle(), use it to shut down the server here,
        //       and remove the shutdown timeout
    });

    info!("waiting for RPC server to shut down...");
    rt.shutdown_timeout(Duration::from_secs(1));
}

/// Test that the JSON-RPC server spawns when configured with a single thread,
/// on an OS-assigned unallocated port.
#[test]
fn rpc_server_spawn_unallocated_port_single_thread() {
    rpc_server_spawn_unallocated_port(false)
}

/// Test that the JSON-RPC server spawn when configured with multiple threads,
/// on an OS-assigned unallocated port.
#[test]
fn rpc_sever_spawn_unallocated_port_parallel_threads() {
    rpc_server_spawn_unallocated_port(true)
}

/// Test if the RPC server will spawn on an OS-assigned unallocated port.
///
/// Set `parallel_cpu_threads` to true to auto-configure based on the number of CPU cores.
#[tracing::instrument]
fn rpc_server_spawn_unallocated_port(parallel_cpu_threads: bool) {
    let _init_guard = zebra_test::init();

    let port = zebra_test::net::random_unallocated_port();
    let config = Config {
        listen_addr: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into()),
        parallel_cpu_threads: if parallel_cpu_threads { 0 } else { 1 },
    };

    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        let mut mempool: MockService<_, _, _, BoxError> = MockService::build().for_unit_tests();
        let mut state: MockService<_, _, _, BoxError> = MockService::build().for_unit_tests();

        info!("spawning RPC server...");

        let (rpc_server_task_handle, rpc_tx_queue_task_handle) = RpcServer::spawn(
            config,
            "RPC server test",
            Buffer::new(mempool.clone(), 1),
            Buffer::new(state.clone(), 1),
            NoChainTip,
            Mainnet,
        );

        info!("spawned RPC server, checking services...");

        mempool.expect_no_requests().await;
        state.expect_no_requests().await;

        // The server and queue tasks should continue without errors or panics
        let rpc_server_task_result = rpc_server_task_handle.now_or_never();
        assert!(matches!(rpc_server_task_result, None));

        let rpc_tx_queue_task_result = rpc_tx_queue_task_handle.now_or_never();
        assert!(matches!(rpc_tx_queue_task_result, None));

        // TODO: when we return server.close_handle(), use it to shut down the server here
        //       and remove the shutdown timeout
    });

    info!("waiting for RPC server to shut down...");
    rt.shutdown_timeout(Duration::from_secs(1));
}

/// Test if the RPC server will panic correctly when there is a port conflict.
#[test]
#[should_panic(expected = "Unable to start RPC server")]
fn rpc_server_spawn_port_conflict() {
    let _init_guard = zebra_test::init();

    let port = zebra_test::net::random_known_port();
    let config = Config {
        listen_addr: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into()),
        parallel_cpu_threads: 1,
    };

    let rt = tokio::runtime::Runtime::new().unwrap();

    let test_task_handle = rt.spawn(async {
        let mut mempool: MockService<_, _, _, BoxError> = MockService::build().for_unit_tests();
        let mut state: MockService<_, _, _, BoxError> = MockService::build().for_unit_tests();

        info!("spawning RPC server 1...");

        let (_rpc_server_1_task_handle, _rpc_tx_queue_1_task_handle) = RpcServer::spawn(
            config.clone(),
            "RPC server 1 test",
            Buffer::new(mempool.clone(), 1),
            Buffer::new(state.clone(), 1),
            NoChainTip,
            Mainnet,
        );

        tokio::time::sleep(Duration::from_secs(3)).await;

        info!("spawning conflicted RPC server 2...");

        let (rpc_server_2_task_handle, _rpc_tx_queue_2_task_handle) = RpcServer::spawn(
            config,
            "RPC server 2 conflict test",
            Buffer::new(mempool.clone(), 1),
            Buffer::new(state.clone(), 1),
            NoChainTip,
            Mainnet,
        );

        info!("spawned RPC servers, checking services...");

        mempool.expect_no_requests().await;
        state.expect_no_requests().await;

        // Because there is a panic inside a multi-threaded executor,
        // we can't depend on the exact behaviour of the other tasks,
        // particularly across different machines and OSes.

        // The second server should panic, so its task handle should return the panic
        let rpc_server_2_task_result = rpc_server_2_task_handle.await;
        match rpc_server_2_task_result {
            Ok(()) => panic!(
                "RPC server with conflicting port should exit with an error: \
                 unexpected Ok result"
            ),
            Err(join_error) => match join_error.try_into_panic() {
                Ok(panic_object) => panic::resume_unwind(panic_object),
                Err(cancelled_error) => panic!(
                    "RPC server with conflicting port should exit with an error: \
                     unexpected JoinError: {cancelled_error:?}"
                ),
            },
        }

        // Ignore the queue task result
    });

    // Wait until the spawned task finishes
    std::thread::sleep(Duration::from_secs(10));

    info!("waiting for RPC server to shut down...");
    rt.shutdown_timeout(Duration::from_secs(3));

    match test_task_handle.now_or_never() {
        Some(Ok(_never)) => unreachable!("test task always panics"),
        None => panic!("unexpected test task hang"),
        Some(Err(join_error)) => match join_error.try_into_panic() {
            Ok(panic_object) => panic::resume_unwind(panic_object),
            Err(cancelled_error) => panic!(
                "test task should exit with a RPC server panic: \
                 unexpected non-panic JoinError: {cancelled_error:?}"
            ),
        },
    }
}

/// Check if the RPC server detects a port conflict when running parallel threads.
///
/// If this test fails, that's great!
/// We can make parallel the default, and remove the warnings in the config docs.
#[test]
fn rpc_server_spawn_port_conflict_parallel_auto() {
    let _init_guard = zebra_test::init();

    let port = zebra_test::net::random_known_port();
    let config = Config {
        listen_addr: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into()),
        parallel_cpu_threads: 2,
    };

    let rt = tokio::runtime::Runtime::new().unwrap();

    let test_task_handle = rt.spawn(async {
        let mut mempool: MockService<_, _, _, BoxError> = MockService::build().for_unit_tests();
        let mut state: MockService<_, _, _, BoxError> = MockService::build().for_unit_tests();

        info!("spawning parallel RPC server 1...");

        let (_rpc_server_1_task_handle, _rpc_tx_queue_1_task_handle) = RpcServer::spawn(
            config.clone(),
            "RPC server 1 test",
            Buffer::new(mempool.clone(), 1),
            Buffer::new(state.clone(), 1),
            NoChainTip,
            Mainnet,
        );

        tokio::time::sleep(Duration::from_secs(3)).await;

        info!("spawning parallel conflicted RPC server 2...");

        let (rpc_server_2_task_handle, _rpc_tx_queue_2_task_handle) = RpcServer::spawn(
            config,
            "RPC server 2 conflict test",
            Buffer::new(mempool.clone(), 1),
            Buffer::new(state.clone(), 1),
            NoChainTip,
            Mainnet,
        );

        info!("spawned RPC servers, checking services...");

        mempool.expect_no_requests().await;
        state.expect_no_requests().await;

        // Because there might be a panic inside a multi-threaded executor,
        // we can't depend on the exact behaviour of the other tasks,
        // particularly across different machines and OSes.

        // The second server doesn't panic, but we'd like it to.
        // (See the function docs for details.)
        let rpc_server_2_task_result = rpc_server_2_task_handle.await;
        match rpc_server_2_task_result {
            Ok(()) => info!(
                "Parallel RPC server with conflicting port should exit with an error: \
                 but we're ok with it ignoring the conflict for now"
            ),
            Err(join_error) => match join_error.try_into_panic() {
                Ok(panic_object) => panic::resume_unwind(panic_object),
                Err(cancelled_error) => info!(
                    "Parallel RPC server with conflicting port should exit with an error: \
                     but we're ok with it ignoring the conflict for now: \
                     unexpected JoinError: {cancelled_error:?}"
                ),
            },
        }

        // Ignore the queue task result
    });

    // Wait until the spawned task finishes
    std::thread::sleep(Duration::from_secs(10));

    info!("waiting for parallel RPC server to shut down...");
    rt.shutdown_timeout(Duration::from_secs(3));

    match test_task_handle.now_or_never() {
        Some(Ok(())) => {
            info!("parallel RPC server task successfully exited");
        }
        None => panic!("unexpected test task hang"),
        Some(Err(join_error)) => match join_error.try_into_panic() {
            Ok(panic_object) => panic::resume_unwind(panic_object),
            Err(cancelled_error) => info!(
                "Parallel RPC server with conflicting port should exit with an error: \
                 but we're ok with it ignoring the conflict for now: \
                 unexpected JoinError: {cancelled_error:?}"
            ),
        },
    }
}
