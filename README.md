# Process Sentinel
The Process Sentinel is the piece of software that iterates over running processes, and then concludes if it is suspicious.
Through its operation it assess the following parameters:
- software packaging,
- self-modification of `.text` section
- presence of writable and executable memory regions within process memory
- external connections


Result are written in separate files in the `tmp/procsent`:
- `main_log` -- general information about analyzed processes
- `<PID>-<process_name>-<unique_id>` -- detailed results for the particular process



## :star: How to run it
```
user@host $ sudo ./procsent.py &
[<job_number>] + <PID> sudo ./procsent.py
user@host $ disown %<job_number>
```


# Related Projects
1. [Dataset of Packed ELF files](https://github.com/packing-box/dataset-packed-elf)
2. [Bintropy](https://github.com/packing-box/bintropy)
