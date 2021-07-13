# ckb-standalone-debugger
A standalone debugger enabling off-chain contract development. Both a separate library, and a standalone binary is available for use.

# Usage

For Rust library usage, refer to the included tests, they are quite self-explanatory.

See the command line help part for usage on the binary debugger:

```
ckb-debugger 0.5.0-rc1

USAGE:
    ckb-debugger [FLAGS] [OPTIONS] --script-group-type <script-group-type> --tx-file <tx-file>

FLAGS:
        --help       Prints help information
    -s, --step       Set to true to enable step mode, where we print PC address for each instruction
    -V, --version    Prints version information

OPTIONS:
    -i, --cell-index <cell-index>                  Index of cell to run
    -e, --cell-type <cell-type>                    Type of cell to run [possible values: input, output]
    -d, --dump-file <dump-file>                    Dump file name
    -l, --listen <listen>                          Address to listen for GDB remote debugging server
    -c, --max-cycle <max-cycle>                    Max cycles [default: 70000000]
    -r, --replace-binary <replace-binary>          File used to replace the binary denoted in the script
    -g, --script-group-type <script-group-type>    Script group type [possible values: lock, type]
    -h, --script-hash <script-hash>                Script hash
        --script-version <script-version>          Script version
        --skip-end <skip-end>                      End address to skip printing debug info
        --skip-start <skip-start>                  Start address to skip printing debug info
    -t, --tx-file <tx-file>                        Filename containing JSON formatted transaction dump
```

[ckb-transaction-dumper](https://github.com/xxuejie/ckb-transaction-dumper) can be used to dump the full mocked transaction used in the debugger from CKB.
