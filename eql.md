# EQL

#### **Cheatsheet** <a href="#cheatsheet" id="cheatsheet"></a>

**1. Basic Query Format**

* Start with an event type followed by a `where` clause for conditions.

**2. Filtering**

* Use `where` to filter results based on a condition.

**3. Event Joining**

* Use `sequence` to correlate events in a sequence.

**4. Time Constraints**

* Use `until` and `within` to define time constraints between sequence events.

**5. Event Type Definition**

* Define event types to filter on specific log types.

**6. Field Comparisons**

* Use field comparisons to correlate fields within and across events.

**7. String Functions**

* Use string functions like `concat`, `substring`, etc., for string operations.

**8. Mathematical Operations**

* Use mathematical operations like `+`, `-`, `*`, `/` for calculations.

**9. Logical Operators**

* Use logical operators like `and`, `or`, `not` for complex conditions.

**10. Pipe Operations**

```
Use `|` to perform operations like filtering, sorting, and counting on the query results.
```

#### Examples for Detection Query in EQL <a href="#examples-for-detection-query-in-eql" id="examples-for-detection-query-in-eql"></a>

**1. Basic Query**

```
process where process_name == "cmd.exe"
```

**2. Event Sequence**

```
sequence by host.id
    [process where process_name == "cmd.exe"]
    [network where process_name == "cmd.exe" and port == 80]
```

**3. Time Constraint**

```
sequence by host.id
    [process where process_name == "cmd.exe"]
    [network where process_name == "cmd.exe" and port == 80] within 1m
```

**4. Field Comparison**

```
sequence by host.id
    [process where process_name == "cmd.exe"]
    [network where process_name == "cmd.exe" and port == 80 and process.pid == process.parent_pid]
```

**5. String Concatenation**

```
process where concat(process_name, " ", process.args) == "cmd.exe /c"
```

**6. Logical Operator**

```
process where process_name == "cmd.exe" and not user.name == "SYSTEM"
```

**7. Mathematical Operation**

```
file where file.size + 100 > 2000
```

**8. Event Type Definition**

```
file where opcode == "create" and file.extension == "exe"
```

**9. Pipe and Count**

```
process where process_name == "cmd.exe"
| count
```

**10. Pipe and Unique Count**

```
process where true
| unique_count user.name
```

**11. Pipe and Sort**

```
process where true
| sort process.start_time desc
```

**12. Pipe and Filter**

```
process where true
| filter process_name == "cmd.exe"
```

**13. Pipe and Head**

```
process where true
| head 5
```

**14. Pipe and Tail**

```
process where true
| tail 5
```

**15. Subquery**

```
process where process_name == "cmd.exe" and
    [file where file_name == "evil.exe"]
```

**16. Wildcard Usage**

```
process where process_name like "svchost.*"
```

**17. Case Insensitive Match**

```
process where process_name : "Cmd.ExE"
```

**18. Length Function**

```
process where length(process_name) > 5
```

**19. Number Function**

```
process where number(process_name) == 123
```

**20. Array Function**

```
process where array_length(process.args) > 2
```
