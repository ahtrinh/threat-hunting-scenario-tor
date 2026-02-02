# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/ahtrinh/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2024-11-08T22:27:19.7259964Z`. These events began at `2024-11-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "alex-mde-test" 
| where FileName contains "tor"
| where Timestamp >= datetime('2026-01-31T01:44:45.2752322Z')
| order by TimeGenerated desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="847" height="278" alt="image" src="https://github.com/user-attachments/assets/1b17d5a5-432d-4cb3-a8a8-320c84b10fd2" />



---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "alex-mde-test"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.5.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="848" height="101" alt="image" src="https://github.com/user-attachments/assets/3d5529f3-84b5-4b54-8c2c-8de9aca9bc39" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "alex-mde-test"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp
```
<img width="848" height="533" alt="image" src="https://github.com/user-attachments/assets/8f03ea2c-b23a-4adb-bb6a-27394463c55d" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "alex-mde-test"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountDomain, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="848" height="159" alt="image" src="https://github.com/user-attachments/assets/fdd6f100-d16d-4140-9c40-1f6f2284a949" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-01-31T01:44:45.2752322Z`
- **Event:** The employee ahtrinh downloaded Tor-related files, including a Tor Browser portable installer, and multiple files containing the string “tor” were created or copied to the desktop.
- **Action:** File download detected.
- **File Path:** `c:\users\ahtrinh\desktop\Tor-browser-windows-x86_64-portable-15.0.5.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-01-31T01:46:51.4770009Z`
- **Event:** The employee executed the Tor Browser portable installer tor-browser-windows-x86_64-portable-15.0.5.exe, initiating extraction of the Tor Browser files.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.5.exe /S`
- **File Path:** `C:\Users\ahtrinh\Downloads\tor-browser-windows-x86_64-portable-15.0.5.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-01-31T01:47:25.4514034Z`
- **Event:** The employee ahtrinh launched the Tor Browser. Tor-related processes, including firefox.exe and tor.exe, were spawned, indicating successful browser startup.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\ahtrinh\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-01-31T01:47:41.5282597Z`
- **Event:** A successful outbound network connection was established to the external IP address 144.76.104.119 over port 9001 using the Tor process, confirming Tor relay communication.
Action: Connection success detected.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\ahtrinh\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-01-31T01:47:30.6990117Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\ahtrinh\Desktop\tor-shopping-list.txt`

---

## Summary

The user employee downloaded and executed the Tor Browser portable installer on the endpoint alex-mde-test, resulting in the extraction of multiple Tor-related files to the desktop. Shortly after execution, the employee launched the Tor Browser, which spawned Tor-specific processes including firefox.exe and tor.exe from the Tor Browser directory. Network telemetry confirmed that the Tor process successfully established outbound connections to external hosts, including communication over port 9001, a port commonly associated with Tor relay traffic, as well as additional encrypted connections over port 443. The sequence of file creation, process execution, and network activity is consistent with intentional and active use of the Tor network by the employee rather than incidental or background system behavior.

---

## Response Taken

TOR usage was confirmed on endpoint alex-mde-test by the user. The device was isolated and the user's direct manager was notified.
