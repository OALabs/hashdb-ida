<p align="center">
<img src="https://user-images.githubusercontent.com/5906222/134734091-5640ba7e-ac08-423e-8e7d-983ffc044a18.gif">
</p>

[![GitHub release](https://img.shields.io/github/v/release/oalabs/hashdb-ida.svg)](https://github.com/OALabs/hashdb-ida/releases) [![Chat](https://img.shields.io/badge/chat-Discord-blueviolet)](https://discord.gg/cw4U3WHvpn) 

# HashDB IDA Plugin
Malware string hash lookup plugin for IDA Pro. This plugin connects to the OALABS [HashDB Lookup Service](https://hashdb.openanalysis.net). 

## Adding New Hash Algorithms
The hash algorithm database is open source and new algorithms can be added on [GitHub here](https://github.com/OALabs/hashdb). Pull requests are mostly automated and as long as our automated tests pass the new algorithm will be usable on HashDB within minutes.

## Using HashDB
HashDB can be used to look up strings that have been hashed in malware by right-clicking on the hash constant in the IDA disassembly view and launching the `HashDB Lookup` client. 

### Settings
Before the plugin can be used to look up hashes the HashDB settings must be configured. The settings window can be launched from the plugins menu `Edit->Plugins->HashDB`.

<p align="center">
<img width="516" alt="Screen Shot 2021-09-24 at 4 23 19 PM" src="https://user-images.githubusercontent.com/5906222/134735719-3c08b87f-313e-4805-aae1-3e440da9ddc2.png">
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
<img width="381" alt="Screen Shot 2021-09-24 at 4 23 47 PM" src="https://user-images.githubusercontent.com/5906222/134736795-649c6845-ece6-4a46-903e-cf7c0efa3324.png">
 </p>

### Bulk Import
If a hash is part of a module a prompt will ask if you want to import all the hashes from that module. This is a quick way to pull hashes in bulk. For example, if one of the hashes identified is `Sleep` from the `kernel32` module, HashDB can then pull all the hashed exports from `kernel32`.

<p align="center">
<img width="367" alt="Screen Shot 2021-09-24 at 4 24 06 PM" src="https://user-images.githubusercontent.com/5906222/134738243-b4a6b8f2-2784-4a8a-9393-e7b676655249.png">
</p>

### Algorithm Search
HashDB also includes a basic algorithm search that will attempt to identify the hash algorithm based on a hash value. **The search will return all algorithms that contain the hash value, it is up to the analyst to decide which (if any) algorithm is correct.** To use this functionality right-click on the hash constant and select `HashDB Hunt Algorithm`.

<p align="center">
<img width="285" alt="Screen Shot 2021-09-29 at 5 34 05 PM" src="https://user-images.githubusercontent.com/5906222/135352570-771f5b03-4730-41e3-9757-a32ad31bec3b.png">
</p>

All algorithms that contain this hash will be displayed in a chooser box. The chooser box can be used to directly select the algorithm for HashDB to use. If `Cancel` is selected no algorithm will be selected.

<p align="center">
<img width="370" alt="Screen Shot 2021-09-29 at 5 34 31 PM" src="https://user-images.githubusercontent.com/5906222/135352732-4a18ee03-c1f3-4a67-9c80-811121365448.png">
</p>

## Installing HashDB 
Before using the plugin you must install the python **requests** module in your IDA environment. The simplest way to do this is to use pip from a shell outside of IDA.  
`pip install requests`

Once you have the requests module installed simply copy the latest release of [`hashdb.py`](https://github.com/OALabs/hashdb-ida/releases) into your IDA plugins directory and you are ready to start looking up hashes!


## ❗Compatibility Issues
The HashDB plugin has been developed for use with the __IDA 7+__ and __Python 3__ it is not backwards compatible. 

