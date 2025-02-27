# adaptive_rootCause_analysis
## Prerequisites

- Ensure you have the following installed on your system:
- Ubuntu/Debian-based system
- GCC (GNU Compiler Collection)
- LTTng tools and libraries

## Installation

Install LTTng and Dependencies

Reference: LTTng Documentation
```
sudo apt update
sudo apt install lttng-tools liblttng-ust-dev liblttng-ctl-dev
```
## Compilation

Compile notif-app.c

Ensure notif-app.c is present in the repository, then compile it with:
```
gcc -o notif-app notif-app.c -L/usr/local/lib -llttng-ctl
```
Setting Up LTTng Trigger

## Create the LTTng Trigger

Run the following command to set up an event notification trigger:
```
lttng add-trigger --name=sched-switch-notif3 \
    --condition=event-rule-matches \
    --type=user --name=jaeger_ust:start_span \
    --filter='op_name == "HTTP GET /dispatch"' \
    --capture=op_name \
    --action=notify
```
## Creating an LTTng Session

Initialize and Start the Tracing Session

```
lttng create my-session  
lttng enable-event --userspace --all  
lttng start
```

### Running the Notification Application

Execute the compiled notification application with the trigger:
```
./notif-app sched-switch-notif3
```
### Verification

Check Active LTTng Sessions
```
lttng list
```
Check Active Triggers
```
lttng list-triggers
```

### Stopping and Cleaning Up

Stop and Destroy the Session
```
lttng stop  
lttng destroy my-session
```
