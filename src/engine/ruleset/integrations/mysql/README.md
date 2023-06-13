# MySQL Server integration


|   |   |
|---|---|
| event.module | mysql |
| event.dataset | mysql.error, mysql.slowlog |

This integration processes the following logs from [MySQL](https://dev.mysql.com/) Server:
  - MySQL Error logs: contains a record of mysqld startup and shutdown times. It also contains diagnostic messages such as errors, warnings, and notes that occur during server startup and shutdown, and while the server is running. For example, if mysqld notices that a table needs to be automatically checked or repaired, it writes a message to the error log.
  - MySQL Slow Query logs: consists of SQL statements that take more than `long_query_time` seconds to execute and require at least `min_examined_row_limit` rows to be examined. The slow query log can be used to find queries that take a long time to execute and are therefore candidates for optimization.


## Compatibility

The integration was tested with MySQL server logs from version 5.7 and 8.0

## Configuration

This integration uses the logcollector source localfile to ingest the logs from `/var/log/mysql/error.log` and `/var/log/mysql/mysql-slow.log` (the location of the files can be configured in the localfile configuration).
Adding to the ossec.conf file in the monitored agent the following blocks:

```xml
<localfile>
  <log_format>multi-line-regex</log_format>
  <!-- Edit location to appropriate path if needed -->
  <location>/var/log/mysql/error.log</location>
  <multiline_regex>^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{6}Z|^\d{6} \d{2}:\d{2}:\d{2}</multiline_regex>
</localfile>

<localfile>
  <log_format>multi-line-regex</log_format>
  <!-- Edit location to appropriate path if needed -->
  <location>/var/log/mysql/mysql-slow.log</location>
  <multiline_regex>^# Time:</multiline_regex>
</localfile>
```


## Schema

## Decoders

| Name | Description |
|---|---|
| decoder/mysql-slowlog/0 | Decoder for MySQL Server Slow Query logs |
| decoder/mysql-error/0 | Decoder for MySQL Server error logs |
## Rules

| Name | Description |
|---|---|
## Outputs

| Name | Description |
|---|---|
## Filters

| Name | Description |
|---|---|
## Changelog

| Version | Description | Details |
|---|---|---|
| 0.0.1-dev | Created integration for MySQL | [#17404](https://github.com/wazuh/wazuh/pull/17404) |