# Fuzzing

While avbroot's parsers are all memory-safe, it is still possible for panics or crashes to occur, for example due to excessive memory allocation, integer overflow, or division by zero. Fuzzing helps to identify these issues by randomizing inputs in a way that tries to increase code coverage.

## Running the fuzzers

1. Install the cargo honggfuzz commands.

    ```bash
    cargo install honggfuzz
    ```

2. [Optional] Generate sample files to use as the initial fuzzing corpus.

    ```bash
    cargo xtask fuzz-corpus
    ```

3. Pick a fuzz target to run. A fuzz target is the name of the source file in [`src/bin/`](./src/bin) without the `.rs` extension.

    The list of targets can be queried programmatically with:

    ```bash
    cargo read-manifest | jq -r '.targets[].name'
    ```

4. Run the fuzzer.

    ```bash
    cargo hfuzz run <fuzz target>
    ```

    This will run forever until it is manually killed. At the top of the screen, a summary section like the following is shown:

    ```
      Iterations : 31,243 [31.24k]
      Mode [1/3] : Feedback Driven Dry Run [2486/4085]
          Target : hfuzz_target/x86_64-unknown-linux-gnu/release/bootimage
         Threads : 8, CPUs: 16, CPU%: 800% [50%/CPU]
           Speed : 36,126/sec [avg: 31,243]
         Crashes : 53 [unique: 1, blocklist: 0, verified: 0]
        Timeouts : 0 [1 sec]
     Corpus Size : 1,424, max: 24,576 bytes, init: 4,085 files
      Cov Update : 0 days 00 hrs 00 mins 00 secs ago
        Coverage : edge: 897/224,621 [0%] pc: 2 cmp: 34,736
    ```

    When a crash occurs, the `Crashes` counter will increment and the input data that triggered the crash will be written to `hfuzz_workspace/<fuzz target>/*.fuzz`. New files are only written for unique crashes.

5. If a crash occurs, run the following command to trigger the crash in a debugger.

    ```bash
    cargo hfuzz run-debug <fuzz target> \
        hfuzz_workspace/<fuzz_target>/<input file>.fuzz
    ```

    This defaults to using `rust-lldb`. To use `rust-gdb` instead, set the `HFUZZ_DEBUGGER` environment variable to `rust-gdb`.

    Alternatively, just feed the input file to the appropriate avbroot command directly (eg. `avbroot boot info -i hfuzz_workspace/<fuzz_target>/<input file>.fuzz` for boot images).
