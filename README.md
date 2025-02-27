# Adaptive_rootCause_analysis
https://lttng.org/docs/v2.13/#doc-trigger-event-notif
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
lttng create my-session --output="your direct location"  
lttng enable-event --userspace --all

lttng enable-event -c kernelchannel -k sched_switch,sched_waking,sched_pi_setprio,sched_process_fork,sched_process_exit,sched_process_free,sched_wakeup,\
irq_softirq_entry,irq_softirq_raise,irq_softirq_exit,irq_handler_entry,irq_handler_exit,\
lttng_statedump_process_state,lttng_statedump_start,lttng_statedump_end,lttng_statedump_network_interface,lttng_statedump_block_device,\
block_rq_complete,block_rq_insert,block_rq_issue,\
block_bio_frontmerge,sched_migrate,sched_migrate_task,power_cpu_frequency,\
net_dev_queue,netif_receive_skb,net_if_receive_skb,\
timer_hrtimer_start,timer_hrtimer_cancel,timer_hrtimer_expire_entry,timer_hrtimer_expire_exit

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
