# KQL

#### **Cheatsheet** <a href="#cheatsheet" id="cheatsheet"></a>

**1. Basic Query Format**

* Start with the table name followed by a series of query operators.

**2. Filtering**

* Use `where` to filter results based on a condition.

**3. Sorting**

* Use `order by` to sort results based on a column.

**4. Aggregation**

* Use `summarize` to aggregate data.

**5. Joining Tables**

* Use `join` to combine tables based on a related column.

**6. Selecting Columns**

* Use `project` to select which columns to display.

**7. Renaming Columns**

* Use `extend` or `project` with `as` to rename columns.

**8. Limiting Results**

* Use `take` to limit the number of results returned.

**9. Calculating Time Difference**

* Use `datetime_diff` to calculate the difference between two datetime columns.

**10. String Manipulation**

```
Use `strcat`, `substring`, etc., for string operations.
```

#### Examples for Detection Query in KQL <a href="#examples-for-detection-query-in-kql" id="examples-for-detection-query-in-kql"></a>

**1. Basic Query**

**2. Filter for a Specific Event ID**

```
SecurityEvent
| where EventID == 4624
```

**3. Retrieve Specific Columns**

```
SecurityEvent
| project TimeGenerated, Computer, EventID
```

**4. Count by Event ID**

```
SecurityEvent
| summarize count() by EventID
```

**5. Filter and Sort by Time**

```
SecurityEvent
| where EventID == 4624
| order by TimeGenerated desc
```

**6. Join Two Tables**

```
SecurityEvent
| join (
    Syslog
) on Computer
```

**7. Limit Results**

**8. Calculate Time Difference**

```
SecurityEvent
| extend duration = datetime_diff('second', TimeGenerated, TimeGenerated)
```

**9. String Concatenation**

```
SecurityEvent
| extend info = strcat(Computer, ":", EventID)
```

**10. Filter with Multiple Conditions**

```
SecurityEvent
| where EventID == 4624 and Computer == "MY-PC"
```

**11. Count Events per Computer**

```
SecurityEvent
| summarize count() by Computer
```

**12. Filter for a Specific Time Range**

```
SecurityEvent
| where TimeGenerated between (datetime(2022-01-01) .. datetime(2022-01-31))
```

**13. Find Unique Values**

```
SecurityEvent
| summarize count() by Account
| project Account
```

**14. Calculate Average**

```
Perf
| summarize avg(CounterValue) by CounterName
```

**15. Group by Time Interval**

```
SecurityEvent
| summarize count() by bin(TimeGenerated, 1h)
```

**16. Use of Case Statement**

```
SecurityEvent
| extend EventType = case(EventID == 4624, "Login", EventID == 4625, "Failed Login", "Other")
```

**17. Filter with String Contains**

```
SecurityEvent
| where Computer contains "MY-PC"
```

**18. Top N Entities**

```
SecurityEvent
| summarize count() by Computer
| top 5 by count_
```

**19. Calculate Percentage**

```
SecurityEvent
| summarize EventCount = count() 
| extend Percentage = EventCount * 100 / toscalar(SecurityEvent | count())
```

**20. Filter with Not Equal**

```
SecurityEvent
| where Computer != "MY-PC"
```
