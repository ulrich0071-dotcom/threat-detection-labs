# Windows New User Creation (EventCode 4720)

## Goal
Detect whenever a new user account is created in Windows, because attackers often create hidden users for persistence.

## Raw view (what happened)
```spl
index=winsec EventCode=4720
| table _time, host, Message
| sort - _time

Summary view (which machines are affected)
index=winsec EventCode=4720
| stats count by host
| sort - count

How to test (lab)
Create a test user:
net user testuser Test@123 /add

Delete it after testing:
net user testuser /delete


