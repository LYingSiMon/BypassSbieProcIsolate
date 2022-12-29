# BypassSbieProcIsolate
The purpose of this project is to investigate some ways that process isolation can be bypassed in sandboxie. Then limit the number of own processes in the sandbox.This is a long-term project and I will continue to update it.

## True purpose
sandboxie has some inadequacies in process isolation. This project was designed to detect sandboxie's process isolation weaknesses and try to fix them.

## method for detecting the number of own processes
+ process enum (Or other features of the process, such as window features)
+ inter process Communication inside (such as Shared memory, socket ...)
+ inter process Communication outside (such as file, regedit ...)
+ Resource exclusives can also be used if only one process is allowed to open

## warning
Since this is test code, there are some coding specification issues. 
And I'm not going to fix them 🙄

## todo
modify sandboxie code to Plug these holes.
