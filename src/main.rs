use std::{path::PathBuf, time::Duration};

use libafl::{
    feedback_and_fast, feedback_or,
    prelude::{
        havoc_mutations, tokens_mutations, BytesInput, Corpus, CrashFeedback, ForkserverExecutor,
        HitcountsMapObserver, InMemoryCorpus, MaxMapFeedback, OnDiskCorpus, SimpleEventManager,
        SimpleMonitor, StdMapObserver, StdScheduledMutator, TimeFeedback, TimeObserver,
        TimeoutForkserverExecutor, Tokens,
    },
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
    state::{HasCorpus, HasMetadata, StdState},
    Fuzzer, StdFuzzer,
};

use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Merge},
    AsMutSlice,
};

//https://mmi.hatenablog.com/entry/2019/05/15/183807
//https://epi052.gitlab.io/notes-to-self/tags/libafl/
//https://aflplus.plus/docs/parallel_fuzzing/

//シングルスレッドで実行される
fn main() -> Result<(), libafl::Error> {
    const MAP_SIZE: usize = 65536;

    let mut shmem = StdShMemProvider::new()
        .unwrap()
        .new_shmem(MAP_SIZE)
        .unwrap();

    let map_observer = {
        //afl-ccでコンパイルされたプログラムのカバレッジは、__AFL_SHM_IDの環境変数が示す共有メモリ名に保存される
        //シングルスレッドなので、shmemは１個で大丈夫
        shmem.write_to_env("__AFL_SHM_ID").unwrap();
        let shmem_slice = shmem.as_mut_slice();
        HitcountsMapObserver::new(unsafe { StdMapObserver::new("shmem", shmem_slice) })
    };

    let time_observer = TimeObserver::new("time");

    let (mut fuzzer, mut state) = {
        //新しいカバレッジであるとき、入力コーパスに追加する
        //なおtime_feedbackは、必ずfalseであるので、条件判定に寄与しない
        //ただし、条件判定に寄与しないものの、Testcaseに実行時間のメタデータを付与してくれる
        let mut feedback = {
            //インデックスは追跡するが、Novelty Searchはしない
            //MaxMapFeedback::new(&map_observer)ではなく、tracking(&map_observer, true, false)になっている理由は？
            //広くinterestingを取りたいから？入力コーパスへの追加条件を甘くしている？
            let map_feedback = MaxMapFeedback::tracking(&map_observer, true, false);
            let time_feedback = TimeFeedback::with_observer(&time_observer);
            feedback_or!(map_feedback, time_feedback)
        };

        //クラッシュし、かつ新しいカバレッジであるとき、Bugだと判断する
        let mut objective = {
            let map_feedback = MaxMapFeedback::new(&map_observer);
            let crash_feedback = CrashFeedback::new();
            feedback_and_fast!(map_feedback, crash_feedback)
        };

        let state = {
            //corpusをondiskにした場合、複数のインスタンス間でcorpusを共有できる？
            let corpus = InMemoryCorpus::<BytesInput>::new();
            let solutions = OnDiskCorpus::new(PathBuf::from("./timeouts"))?;
            let rand = StdRand::with_seed(current_nanos());
            StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)
        }?;

        // feedback, objectiveはfuzzerが所有する
        let fuzzer = {
            let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());
            StdFuzzer::new(scheduler, feedback, objective)
        };

        (fuzzer, state)
    };

    let mut stages = {
        //havoc_mutationsはスタンダードなmutationの集合
        let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
        tuple_list!(StdMutationalStage::new(mutator))
    };

    // observerはexecutorが所有する
    let mut executor = {
        //forkserverは典型的なfork -> executeではない
        //プログラムの開始部分で停止し、指示待ちする。支持ありの場合は、forkする
        //そのため、executeのコストを削減できる
        //ForkserverExecutorの場合ははじめのプロセスは、build時に生成される
        //Exexutor::run_targetでは、はじめのプロセスにforkの指示を送るだけ
        let executor = ForkserverExecutor::builder()
            .program("test")
            .parse_afl_cmdline(["@@"])
            .coverage_map_size(MAP_SIZE)
            .build(tuple_list!(map_observer, time_observer))?;

        let timeout = Duration::from_secs(5);
        TimeoutForkserverExecutor::new(executor, timeout)?
    };

    let mut manager = {
        let monitor = SimpleMonitor::new(|s| println!("{s}"));
        SimpleEventManager::new(monitor)
    };

    //最初のコーパスのみはディスクからロードする。以降はon-memory
    if state.corpus().count() < 1 {
        let corpus_dirs = vec![PathBuf::from("./corpus")];

        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut manager, &corpus_dirs)
            .unwrap_or_else(|err| {
                panic!(
                    "Failed to load initial corpus at {:?}: {:?}",
                    &corpus_dirs, err
                )
            });
    }

    if state.metadata_map().get::<Tokens>().is_none() {
        let token_dirs = vec![PathBuf::from("./token")];
        let tokens = Tokens::new().add_from_files(token_dirs)?;
        state.add_metadata(tokens);
    }

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut manager)?;
    Ok(())
}
