```markdown
# Cute Wazuh Rules

## Lock and Unlock Events
- **Rule ID:** 100003
  - **Group:** windows, event logs, lock
  - **Level:** 10
  - **Condition:** If Security IDs (SIDs) match 60000,60001,60017,60103 and Windows system event ID matches 4800
  - **Description:** Windows workstation locked

- **Rule ID:** 100004
  - **Group:** windows, event logs, unlock
  - **Level:** 10
  - **Condition:** If SIDs match 60000,60001,60017,60103 and Windows system event ID matches 4801
  - **Description:** Windows workstation unlocked

## Screensaver Events
- **Rule ID:** 100005
  - **Group:** windows, event logs
  - **Level:** 10
  - **Condition:** If SIDs match 60000,60001,60017,60103 and Windows system event ID matches 4802
  - **Description:** Windows screensaver invoked

- **Rule ID:** 100006
  - **Group:** windows, event logs
  - **Level:** 10
  - **Condition:** If SIDs match 60000,60001,60017,60103 and Windows system event ID matches 4803
  - **Description:** Windows screensaver dismissed

## System Suspension and Time Change Events
- **Rule ID:** 100007
  - **Group:** windows, event logs
  - **Level:** 10
  - **Condition:** If SIDs match 60000,60002,60007,61100 and Windows system event ID matches 42
  - **Description:** System suspension activation in progress

- **Rule ID:** 100008
  - **Group:** windows, event logs
  - **Level:** 10
  - **Condition:** If SIDs match 60000,60002,60007,61100 and Windows system event ID matches 1
  - **Description:** System time has been modified

## Logon Attempt Event
- **Rule ID:** 100009
  - **Group:** windows, event logs
  - **Level:** 10
  - **Condition:** If SIDs match 60000,60001,60017,60103 and Windows system event ID matches 4628
  - **Description:** A logon was attempted using explicit credentials

## Timeframe Check
- **Rule ID:** 100010
  - **Group:** timeframecheck
  - **Level:** 10
  - **Timeframe:** 30 seconds
  - **Condition:** If Rule ID 100004 is matched within 30 seconds of Rule ID 100003
  - **Description:** Workstation unlocked after 30 seconds

- **Rule ID:** 100011
  - **Group:** timeframecheck
  - **Level:** 10
  - **Timeframe:** 60 seconds
  - **Condition:** If Rule ID 100004 is matched within 60 seconds of Rule ID 100003
  - **Description:** Workstation unlocked after 60 seconds
```
