# Debugging

Unfortunately currently the debugging facilities are quite limited. Use
`printf`-style debugging, logging and staring at code...

Here are a few tips:

- Change the log-level of the kernel to info, debug, or even trace: `python3 run.py --cmd='log=info'`
- Change the log-level of the user-space libOS in virbio (search for `Level::`)
- Make sure the [Tests](./Testing.md) run (to see if something broke).