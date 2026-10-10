\# 🛡️ Automated Network Configuration \& Security Compliance Auditor (NetDevOps)



An automated Python-driven network audit and configuration management pipeline. The tool ingests raw Cisco IOS running-configuration snapshots, performs regex-based compliance checks against enterprise security baselines (CIS Benchmark-aligned), generates styled Excel audit reports, and pushes instant rich embed notifications to Discord/Slack webhooks upon rule violations.



\---



\## 📌 Architecture \& Workflow



```text

+------------------------------+

| Cisco Packet Tracer Lab /    |

| Multi-Device Network Estate  |

+------------------------------+

&#x20;              |

&#x20;              v (Extract / Export Snapshots)

+------------------------------+

|       backups/\*.cfg          |

+------------------------------+

&#x20;              |

&#x20;              v

+-------------------------------------------------------------+

|               Python Compliance Engine (main.py)            |

|                                                             |

|  • Rule 1: SSH v2 Enforcement                               |

|  • Rule 2: Password Encryption (service password-encryption)|

|  • Rule 3: Warning Banner Configuration (banner motd)       |

|  • Rule 4: Telnet Disablement (transport input ssh only)    |

+-------------------------------------------------------------+

&#x20;        /                                           \\

&#x20;       v                                             v

+-------------------------------+             +-------------------------------+

|    Executive Excel Report     |             |  Real-time Discord Webhook    |

| (openpyxl Conditional Styling)|             | (Rich Embed Security Alerts)  |

|      reports/\*.xlsx           |             |                               |

+-------------------------------+             +-------------------------------+

