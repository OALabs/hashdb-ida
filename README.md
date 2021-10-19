<p align="center">
    <img alt="Showcase" src="/assets/HashDB-Showcase.gif">
</p>

[![GitHub release](https://img.shields.io/github/v/release/oalabs/hashdb-ida.svg)](https://github.com/OALabs/hashdb-ida/releases) [![Chat](https://img.shields.io/badge/chat-Discord-blueviolet)](https://discord.gg/cw4U3WHvpn) [![Support](https://img.shields.io/badge/Support-Patreon-FF424D)](https://www.patreon.com/oalabs)

# HashDB IDA Plugin
Malware string hash lookup plugin for IDA Pro. This plugin connects to the OALABS [HashDB Lookup Service](https://hashdb.openanalysis.net). 

## Adding New Hash Algorithms
The hash algorithm database is open source and new algorithms can be added on [GitHub here](https://github.com/OALabs/hashdb). Pull requests are mostly automated and as long as our automated tests pass the new algorithm will be usable on HashDB within minutes.

## Using HashDB
HashDB can be used to look up strings that have been hashed in malware by right-clicking on the hash constant in the IDA disassembly view and launching the `HashDB Lookup` client. 

### Settings
Before the plugin can be used to look up hashes the HashDB settings must be configured. The settings window can be launched from the plugins menu `Edit->Plugins->HashDB`.

<p align="center">
    <img alt="Settings" src="/assets/HashDB-Settings.png?raw=true">
</p>

#### Hash Algorithms
Click `Refresh Algorithms` to pull a list of supported hash algorithms from the HashDB API, then select the algorithm used in the malware you are analyzing. 

#### Optional XOR
There is also an option to enable XOR with each hash value as this is a common technique used by malware authors to further obfuscate hashes.

#### API URL
The default API URL for the HashDB Lookup Service is `https://hashdb.openanalysis.net/`. If you are using your own internal server this URL can be changed to point to your server.

#### Enum Name
When a new hash is identified by HashDB the hash and its associated string are added to an **enum** in IDA. This enum can then be used to convert hash constants in IDA to their corresponding enum name. The enum name is configurable from the settings in the event that there is a conflict with an existing enum.

### Hash Lookup
Once the plugin settings have been configured you can right-click on any constant in the IDA disassembly window and look up the constant as a hash. The right-click also provides a quick way to set the XOR value if needed.

<p align="center">
    <img width="380" src="/assets/HashDB-Xor_Key.png?raw=true">
</p>

### Bulk Import
If a hash is part of a module a prompt will ask if you want to import all the hashes from that module. This is a quick way to pull hashes in bulk. For example, if one of the hashes identified is `Sleep` from the `kernel32` module, HashDB can then pull all the hashed exports from `kernel32`.

<p align="center">
    <img width="367" src="/assets/HashDB-Bulk_Import.png?raw=true">
</p>

### Algorithm Search
HashDB also includes a basic algorithm search that will attempt to identify the hash algorithm based on a hash value. **The search will return all algorithms that contain the hash value, it is up to the analyst to decide which (if any) algorithm is correct.** To use this functionality right-click on the hash constant and select `HashDB Hunt Algorithm`.

<p align="center">
    <img width="285" src="/assets/HashDB-Hunt_Algorithm.png?raw=true">
</p>

All algorithms that contain this hash will be displayed in a chooser box. The chooser box can be used to directly select the algorithm for HashDB to use. If `Cancel` is selected no algorithm will be selected.

<p align="center">
    <img width="370" src="/assets/HashDB-Matched_Algorithms.png?raw=true">
</p>

### Dynamic Import Address Table Hash Scanning
Instead of resolving API hashes individually (inline in code) some malware developers will create a block of import hashes in memory. These hashes are then all resolved within a single function creating a dynamic import address table which is later referenced in the code. In these scenarios the **HashDB Scan IAT** function can be used.

<p align="center">
    <img width="800" alt="IAT Scan" src="/assets/HashDB-IAT_Scan.gif?raw=true">
</p>

Simply select the import hash block, right-click and choose `HashDB Scan IAT`. HashDB will attempt to resolve each individual integer type (`DWORD/QWORD`) in the selected range.

## Installing HashDB 
Before using the plugin you must install the python **requests** module in your IDA environment. The simplest way to do this is to use pip from a shell outside of IDA.  
`pip install requests`

Once you have the requests module installed simply copy the latest release of [`hashdb.py`](https://github.com/OALabs/hashdb-ida/releases) into your IDA plugins directory and you are ready to start looking up hashes!


## ❗Compatibility Issues
The HashDB plugin has been developed for use with the __IDA 7+__ and __Python 3__ it is not backwards compatible. 

