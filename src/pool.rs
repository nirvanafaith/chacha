//! 极简工作池：把「按块分组」的任务并行跑完，进度与取消通过 `Job` 共享。
//!
//! 不引入任何依赖：`std::thread` + 原子计数器拉取任务。XP 起就支持的 API。

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

/// 共享进度。UI 线程用定时器轮询，工作线程只写原子量。
pub struct Job {
    total_bytes: u64,
    done_bytes: Mutex<u64>,
    pub total_units: usize,
    pub done_units: AtomicUsize,
    pub cancel: AtomicBool,
    pub current: Mutex<String>,
    pub errors: Mutex<Vec<String>>,
}

impl Job {
    pub fn new(total_bytes: u64, total_units: usize) -> Arc<Job> {
        Arc::new(Job {
            total_bytes,
            done_bytes: Mutex::new(0),
            total_units,
            done_units: AtomicUsize::new(0),
            cancel: AtomicBool::new(false),
            current: Mutex::new(String::new()),
            errors: Mutex::new(Vec::new()),
        })
    }

    /// Accumulate exact bytes without 32-bit truncation or per-task rounding.
    pub fn tick(&self, bytes: u64, name: &str) {
        if let Ok(mut done) = self.done_bytes.lock() {
            *done = done.saturating_add(bytes);
        }
        self.done_units.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut g) = self.current.lock() {
            *g = name.to_string();
        }
    }

    pub fn fail(&self, msg: String) {
        self.cancel();
        if let Ok(mut g) = self.errors.lock() {
            if g.len() < 32 {
                g.push(msg);
            }
        }
    }

    pub fn first_error(&self) -> Option<String> {
        match self.errors.lock() {
            Ok(g) => g.first().cloned(),
            Err(_) => None,
        }
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    pub fn permille(&self) -> usize {
        let d = self.done_bytes();
        let t = self.total_bytes;
        if t == 0 || d >= t {
            1000
        } else {
            ((d as u128 * 1000) / t as u128) as usize
        }
    }

    pub fn done_bytes(&self) -> u64 {
        self.done_bytes.lock().map(|n| *n).unwrap_or(0)
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn done_text(&self) -> String {
        format!(
            "{}/{}",
            self.done_units.load(Ordering::Relaxed),
            self.total_units
        )
    }

    pub fn current_name(&self) -> String {
        match self.current.lock() {
            Ok(g) => g.clone(),
            Err(_) => String::new(),
        }
    }
}

pub fn cpu_count() -> usize {
    let n = std::env::var("NUMBER_OF_PROCESSORS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1);
    if n < 1 {
        1
    } else if n > 16 {
        16
    } else {
        n
    }
}

/// 根据任务数决定线程数：小任务串行，避免线程开销反超收益。
pub fn plan_threads(tasks: usize, bytes: u64) -> usize {
    if tasks <= 1 || bytes < 4 * 1024 * 1024 {
        return 1;
    }
    let by_cpu = cpu_count();
    let by_task = tasks;
    let mut t = if by_cpu < by_task { by_cpu } else { by_task };
    if t > 8 {
        t = 8;
    }
    if t < 1 {
        t = 1;
    }
    t
}

/// 并行执行 `0..n` 的任务。`n` 很小或线程创建失败时退回当前线程串行执行。
pub fn run<F>(n: usize, threads: usize, f: F)
where
    F: Fn(usize) + Sync + Send + 'static,
{
    if n == 0 {
        return;
    }
    if threads <= 1 {
        for i in 0..n {
            f(i);
        }
        return;
    }
    let cursor = Arc::new(AtomicUsize::new(0));
    let body = Arc::new(f);
    let mut handles = Vec::new();
    for _ in 1..threads {
        let cursor = Arc::clone(&cursor);
        let body = Arc::clone(&body);
        let job = move || loop {
            let i = cursor.fetch_add(1, Ordering::Relaxed);
            if i >= n {
                break;
            }
            body(i);
        };
        match thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(job)
        {
            Ok(h) => handles.push(h),
            Err(_) => break,
        }
    }
    loop {
        let i = cursor.fetch_add(1, Ordering::Relaxed);
        if i >= n {
            break;
        }
        (*body)(i);
    }
    for h in handles {
        if let Err(payload) = h.join() {
            std::panic::resume_unwind(payload);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Job;

    #[test]
    fn exact_small_files_and_large_totals() {
        let job = Job::new(1001, 1001);
        for _ in 0..500 { job.tick(1, "small"); }
        assert_eq!(job.done_bytes(), 500);
        assert_eq!(job.permille(), 499);
        let huge = Job::new(8 * 1024 * 1024 * 1024 * 1024, 2);
        huge.tick(4 * 1024 * 1024 * 1024 * 1024, "large");
        assert_eq!(huge.permille(), 500);
        let max = Job::new(u64::MAX, 1);
        max.tick(u64::MAX / 2, "max");
        assert_eq!(max.permille(), 499);
    }
}
