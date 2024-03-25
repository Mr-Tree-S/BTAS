# BTAS

> Blue Team Assistance Script

BTAS is a browser assistant script developed for Security Operations Center (SOC) analysts, designed to fully simplify workflows and significantly enhance efficiency. The script runs on the Tampermonkey extension and integrates multiple practical functions, including rapid response, threat intelligence search, log parsing, and automation, greatly improving the efficiency of analysts.

[中文版本(Chinese version)](README.zh-cn.md)

## Installation & Usage

You can install and update the BTAS script using Greasy Fork by clicking the following links:

-   [BTAS Stable Version](https://greasyfork.org/en/scripts/463908-btas)
-   [BTAS Beta Version](https://greasyfork.org/zh-CN/scripts/469395-btas-beta)

## Function Introduction: Blue Team Enhancement & BTAS

### Main Features

1. **Quick Reply**: Comes with over 10 preset reply templates for common scenarios, supports one-click quick replies, and allows for custom reply content.
2. **Convenience Menu**: Integrates shortcuts for over 10 commonly used tools such as JIRA Search, VirusTotal, AbuseIPDB, and Base64 decoding.
3. **Anomaly Detection**: Detects based on over 400 keyword rules and more than 50 abnormal behaviors, improving analysis accuracy and ensuring no major security alerts are missed.
4. **Log Parsing**: Supports parsing log formats from 19 mainstream security and cloud products (e.g., Cortex XDR, Microsoft Endpoint Defender, and Azure Cloud), covering about 80% of ticket scenarios. It quickly parses raw logs and generates alert summary information for customers; it also integrates a one-click jump function to security platforms, eliminating the need for repeated logins.
5. **Important Field Check**: Checks the Organization field and ATT&CK field to ensure tickets are correctly categorized.
6. **Prompt Sound Notification**: Monitors ticket lists in real-time and plays a notification sound for new or updated tickets, prompting analysts to handle them promptly and minimizing omissions.
7. **Ticket Tracking**: Provides visual reminders for tickets that have not been processed or responded to for a long time (time threshold can be set), ensuring all tickets are handled in a timely manner.
8. **Reminders**: Analysts will be prompted with relevant information when opening specific ticket pages, including customer requirements and SOPs, guiding standardized operations.
9. **Reminders Management System**: Features a backend visual management system where administrators can efficiently add, edit, query, and delete reminders, and provides an audit log function. The system supports matching rules based on 10 different fields, such as customer name, event type, and specific keywords, and has added nearly 100 reminder items.
10. **Multiple Project Support**: Currently implemented in projects in Hong Kong, Shanghai, and Macau, improving the efficiency of the entire SDC Cyber Team.

## Contributions

Developed by Barry before version 0.93, restructured by Jack for version 1.0.1 and subsequent development and maintenance, with Xingyu contributing to development after version 1.3.2.

## License

License: Apache License 2.0
