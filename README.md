
# Custom Wazuh Rules

## 🔒Lock and 🔓Unlock Events 
- **Rule ID:** 100003
  - **Group:** windows, event logs, lock
  - **Level:** 10
  - **Condition:** If Security IDs (SIDs) match 60000,60001,60017,60103 and Windows system event ID matches 4800
  - **Description:** Windows workstation locked
  - **Code**
      ```xml
        <group name="windows, event logs, lock,">
            <rule id="100003" level="10">
                <if_sid>60000,60001,60017,60103</if_sid>
                <field name="win.system.eventID">^4800$</field>
                <description>Windows workstation locked</description>
            </rule>
        </group>
       ```
- **Rule ID:** 100004
  - **Group:** windows, event logs, unlock
  - **Level:** 10
  - **Condition:** If SIDs match 60000,60001,60017,60103 and Windows system event ID matches 4801
  - **Description:** Windows workstation unlocked
  - **Code**
      ```xml
        <group name="windows, event logs, unlock,">
            <rule id="100004" level="10">
                <if_sid>60000,60001,60017,60103</if_sid>
                <field name="win.system.eventID">^4801$</field>
                <description>Windows workstation unlocked</description>
            </rule>
        </group>
       ```
## 🖼Screensaver Events
- **Rule ID:** 100005
  - **Group:** windows, event logs
  - **Level:** 10
  - **Condition:** If SIDs match 60000,60001,60017,60103 and Windows system event ID matches 4802
  - **Description:** Windows screensaver invoked
  - **Code**
      ```xml
        <group name="windows, event logs,">
            <rule id="100005" level="10">
                <if_sid>60000,60001,60017,60103</if_sid>
                <field name="win.system.eventID">^4802$</field>
                <description>Windows screensaver invoked</description>
            </rule>
        </group>
       ```
- **Rule ID:** 100006
  - **Group:** windows, event logs
  - **Level:** 10
  - **Condition:** If SIDs match 60000,60001,60017,60103 and Windows system event ID matches 4803
  - **Description:** Windows screensaver dismissed
  - **Code**
      ```xml
        <group name="windows, event logs,">
            <rule id="100006" level="10">
                <if_sid>60000,60001,60017,60103</if_sid>
                <field name="win.system.eventID">^4803$</field>
                <description>Windows screensaver dismissed</description>
            </rule>
        </group>
       ```
## System ⏸Suspension and 🕐Time Change Events
- **Rule ID:** 100007
  - **Group:** windows, event logs
  - **Level:** 10
  - **Condition:** If SIDs match 60000,60002,60007,61100 and Windows system event ID matches 42
  - **Description:** System suspension activation in progress
  - **Code**
      ```xml
        <group name="windows, event logs,">
            <rule id="100007" level="10">
                 <if_sid>60000,60002,60007,61100</if_sid>
                 <field name="win.system.eventID">^42$</field>
                 <description>System suspension activation in progress</description>
            </rule>
        </group>
       ```
- **Rule ID:** 100008
  - **Group:** windows, event logs
  - **Level:** 10
  - **Condition:** If SIDs match 60000,60002,60007,61100 and Windows system event ID matches 1
  - **Description:** System time has been modified
  - **Code**
      ```xml
        <group name="windows, event logs,">
            <rule id="100008" level="10">
                 <if_sid>60000,60002,60007,61100</if_sid>
                 <field name="win.system.eventID">^1$</field>
                 <description>System time has been modified</description>
            </rule>
        </group>
       ```
## 🔑Logon Attempt Event
- **Rule ID:** 100009
  - **Group:** windows, event logs
  - **Level:** 10
  - **Condition:** If SIDs match 60000,60001,60017,60103 and Windows system event ID matches 4628
  - **Description:** A logon was attempted using explicit credentials
  - **Code**
      ```xml
        <group name="windows, event logs,">
            <rule id="100009" level="10">
                 <if_sid>60000,60001,60017,60103</if_sid>
                 <field name="win.system.eventID">^4628$</field>
                 <description>A logon was attempted using explicit credentials</description>
            </rule>
        </group>
       ```

## ⌚Timeframe Check
### ⚠BIG DESIGN ISSUE⚠
⚠⚠ Wazuh manager has a default analysysd cache of 8192 events that it browses to chech the timeframe rules ⚠⚠
### How Timeframe Works

The `timeframe` attribute in Wazuh rules specifies a period (in seconds) during which certain events must occur in sequence to trigger an alert. For instance, in rules 100010 and 100011:

- **Rule 100010**: This rule checks if a workstation was unlocked (event with ID 100004) within 30 seconds after it was locked (event with ID 100003). If this sequence of events occurs within the specified timeframe, the rule triggers an alert indicating that the workstation was unlocked after 30 seconds.
- **Rule 100011**: Similar to rule 100010, but with a timeframe of 60 seconds. It checks if the workstation was unlocked within 60 seconds after being locked.

These timeframe rules are useful for monitoring specific sequences of events within a defined period, allowing for more granular and contextual alerts.

### Rules
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
  
## Interesting rules logic
- If a rule triggers another rule it will not be displayed.
- If none of the underlying rules are triggered, the alert for this rule will be displayed.
- If two rules have the same triggers wins the first match order by id.


## Creating Dashboards with Tag Clouds

To visualize the latest event or value of a field in a Wazuh dashboard using a tag cloud, follow these steps:

1. **Select the Index Pattern:**
   - Choose the index pattern that matches your Wazuh alerts, for example, `wazuh-alerts-*`.

2. **Configure Metrics:**
   - Add a metric to show the latest event. For this, use the `Max` aggregation on the `@timestamp` field.
   
   ```plaintext
   Metrics:
   - Tag size Max @timestamp
   ```

3. **Configure Buckets:**
   - Add a bucket to display significant terms from the desired field. Here, we use `agent.name` as an example.
   - Set the aggregation to `Significant Terms`.
   - Set the field to `agent.name`.
   - Define the size of the bucket, for example, `3`.

   ```plaintext
   Buckets:
   - Tags
     - Aggregation: Significant Terms
     - Field: agent.name
     - Size: 3
     - Custom label: [optional]
   ```

4. **Advanced Settings:**
   - In the advanced settings, you can further refine the display and behavior of your tag cloud.


By following these steps, you can create a tag cloud in your Wazuh dashboard that highlights the most significant agents based on the latest events.

