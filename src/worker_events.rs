//! Latest-only UI telemetry beside lossless, ordered worker results.
//! Progress never carries a receipt, error, review decision or action authority.
use std::sync::{
    Arc, Mutex, TryLockError,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, SendError, TryRecvError},
};

pub(crate) trait ProgressEvent {
    fn is_progress(&self) -> bool;
}

struct Shared<T> {
    latest: Mutex<Option<T>>,
    receiver_alive: AtomicBool,
}
pub(crate) struct Sender<T> {
    results: mpsc::Sender<T>,
    shared: Arc<Shared<T>>,
}
pub(crate) struct Receiver<T> {
    results: mpsc::Receiver<T>,
    shared: Arc<Shared<T>>,
}

pub(crate) fn channel<T: ProgressEvent>() -> (Sender<T>, Receiver<T>) {
    let (tx, rx) = mpsc::channel();
    let shared = Arc::new(Shared {
        latest: Mutex::new(None),
        receiver_alive: AtomicBool::new(true),
    });
    (
        Sender {
            results: tx,
            shared: shared.clone(),
        },
        Receiver {
            results: rx,
            shared,
        },
    )
}
impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self {
            results: self.results.clone(),
            shared: self.shared.clone(),
        }
    }
}
impl<T: ProgressEvent> Sender<T> {
    pub(crate) fn send(&self, event: T) -> Result<(), SendError<T>> {
        let progress = event.is_progress();
        // Only producers can wait on this lock. No I/O or callback runs under it.
        let mut latest = self.shared.latest.lock().unwrap_or_else(|e| e.into_inner());
        if !self.shared.receiver_alive.load(Ordering::Acquire) {
            return Err(SendError(event));
        }
        if progress {
            *latest = Some(event);
            Ok(())
        } else {
            // A later result supersedes any telemetry preceding it. Serialize
            // this clear/send with producers so old progress cannot reappear.
            *latest = None;
            self.results.send(event)
        }
    }
}
impl<T> Receiver<T> {
    pub(crate) fn try_recv(&self) -> Result<T, TryRecvError> {
        match self.results.try_recv() {
            Ok(event) => Ok(event),
            Err(_) => {
                // A preempted worker must never make the UI wait for its lock.
                let mut latest = match self.shared.latest.try_lock() {
                    Ok(guard) => guard,
                    Err(TryLockError::WouldBlock) => return Err(TryRecvError::Empty),
                    Err(TryLockError::Poisoned(error)) => error.into_inner(),
                };
                // A result may have arrived after the first queue check. All
                // sends hold this lock, so this second check preserves the
                // result-before-later-progress boundary even across that race.
                match self.results.try_recv() {
                    Ok(event) => Ok(event),
                    Err(error) => latest.take().ok_or(error),
                }
            }
        }
    }
}
impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        self.shared.receiver_alive.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time::Duration};
    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        Progress(usize),
        Result(usize),
    }
    impl ProgressEvent for Event {
        fn is_progress(&self) -> bool {
            matches!(self, Self::Progress(_))
        }
    }

    #[test]
    fn a_large_progress_burst_retains_only_the_latest_and_completion_is_not_delayed() {
        let (tx, rx) = channel();
        for n in 0..100_000 {
            tx.send(Event::Progress(n)).unwrap();
        }
        assert_eq!(rx.try_recv(), Ok(Event::Progress(99_999)));
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
        for n in 0..100_000 {
            tx.send(Event::Progress(n)).unwrap();
        }
        tx.send(Event::Result(7)).unwrap();
        drop(tx);
        assert_eq!(rx.try_recv(), Ok(Event::Result(7)));
        assert_eq!(rx.try_recv(), Err(TryRecvError::Disconnected));
    }

    #[test]
    fn result_order_is_lossless_across_clones_and_only_old_telemetry_is_superseded() {
        let (tx, rx) = channel();
        let other = tx.clone();
        for n in 0..128 {
            other.send(Event::Progress(n)).unwrap();
            tx.send(Event::Result(n)).unwrap();
        }
        other.send(Event::Progress(999)).unwrap();
        drop(tx);
        drop(other);
        for n in 0..128 {
            assert_eq!(rx.try_recv(), Ok(Event::Result(n)));
        }
        assert_eq!(rx.try_recv(), Ok(Event::Progress(999)));
        assert_eq!(rx.try_recv(), Err(TryRecvError::Disconnected));
    }

    #[test]
    fn a_preempted_progress_producer_cannot_block_the_receiver() {
        let (_tx, rx) = channel::<Event>();
        let shared = rx.shared.clone();
        let (entered, ready) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let worker = thread::spawn(move || {
            let _held = shared.latest.lock().unwrap();
            entered.send(()).unwrap();
            wait.recv_timeout(Duration::from_secs(3)).unwrap();
        });
        ready.recv_timeout(Duration::from_secs(3)).unwrap();
        for _ in 0..1_000 {
            assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
        }
        release.send(()).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn disconnected_receivers_refuse_both_progress_and_results() {
        let (tx, rx) = channel();
        drop(rx);
        assert_eq!(
            tx.send(Event::Progress(1)).unwrap_err().0,
            Event::Progress(1)
        );
        assert_eq!(tx.send(Event::Result(2)).unwrap_err().0, Event::Result(2));
    }

    #[test]
    fn concurrent_progress_streams_do_not_drop_or_reorder_results_from_either_producer() {
        let (tx, rx) = channel();
        let workers = (0..2)
            .map(|producer| {
                let tx = tx.clone();
                thread::spawn(move || {
                    for n in 0..1_000 {
                        tx.send(Event::Progress(n)).unwrap();
                        tx.send(Event::Result(producer * 1_000 + n)).unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();
        drop(tx);
        for worker in workers {
            worker.join().unwrap();
        }
        let mut received = [Vec::new(), Vec::new()];
        while let Ok(event) = rx.try_recv() {
            match event {
                Event::Result(n) => received[n / 1_000].push(n % 1_000),
                Event::Progress(_) => panic!("final results supersede previous progress"),
            }
        }
        for stream in received {
            assert_eq!(stream, (0..1_000).collect::<Vec<_>>());
        }
    }
}
