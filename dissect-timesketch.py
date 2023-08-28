from dissect.target import plugin  # AGPL-3 licensed

"""
Creates a Logstash filter based on Dissect Target records. It does not support Dynamic records.
"""

plugin_fields = {
    # Hardcoded dynamic records
    # "filesystem/windows/evtx": ["EventID", "Provider_Name"],
    # "filesystem/windows/task": ["Uri", "Command"],
    # "filesystem/windows/amcache/install": ["Filename", "Path"],
    # "filesystem/windows/wer/report": ["App_Name", "Event_Type"],
    # "windows/registry/firewall": ["Key", "Action", "Active", "Dir", "Protocol"],
    # "filesystem/windows/etl": ["Path", "ProviderName", "EventType"],
    # End hardcoded dynamic records
    "filesystem/windows/amcache/install/arp_create": ["Path"],
    "filesystem/windows/amcache/install/file_create": ["Path"],
    "application/log/webserver": [
        "Method",
        "URI",
        "Protocol",
        "Status_Code",
        "Bytes_Sent",
        "Remote_IP",
        "UserAgent",
        "Referer",
    ],
    "browser/chrome/extension": ["Browser", "Name"],
    "browser/chrome/download": ["Browser", "Path", "URL"],
    "browser/chrome/history": ["Browser", "Title", "URL"],
    "browser/chromium/download": ["Browser", "Path", "URL"],
    "browser/chromium/extension": ["Browser", "Name"],
    "browser/chromium/history": ["Browser", "Title", "URL"],
    "browser/edge/download": ["Browser", "Path", "URL"],
    "browser/edge/extension": ["Browser", "Name"],
    "browser/edge/history": ["Browser", "Title", "URL"],
    "browser/firefox/download": ["Browser", "Path", "URL"],
    "browser/firefox/history": ["Browser", "Title", "URL"],
    "browser/ie/download": ["Browser", "Path", "URL"],
    "browser/ie/history": ["Browser", "Title", "URL"],
    "filesystem/entry": ["Path"],
    "filesystem/acquire_hash": ["Path"],
    "filesystem/yara/match": ["Path", "Rule", "Tags"],
    "filesystem/unix/capability": [
        "Record",
        "Permitted",
        "Inheritable",
        "Effective",
        "RootID",
    ],
    "filesystem/unix/suid": ["Path"],
    "filesystem/ntfs/usnjrnl": ["Path", "Reason", "Attr"],
    "filesystem/ntfs/mft/std": ["ts_type", "Path"],
    "filesystem/ntfs/mft/filename/compact": ["Path"],
    "filesystem/ntfs/mft/filename": ["ts_type", "Path"],
    "filesystem/ntfs/mft/std/compact": ["Path"],
    "example/registry/user": ["ts"],
    "example/descriptor": ["field_a"],
    "browser/history": ["Browser", "Title", "Url"],
    "browser/firefox/history": ["Browser", "Title", "Url"],
    "browser/chromium/history": ["Browser", "Title", "Url"],
    "browser/edge/history": ["Browser", "Title", "Url"],
    "browser/ie/history": ["Browser", "Title", "Url"],
    "browser/chrome/history": ["Browser", "Title", "Url"],
    "generic/osinfo": ["Name", "Value"],
    "linux/user": [
        "Name",
        "shell",
        "UID",
        "GID",
    ],
    "linux/service": ["name", "source"],
    "linux/environmentvariable": ["Key", "Value", "Source"],
    "linux/cronjob": ["command"],
    "linux/keyboard": ["layout", "model", "variant", "options", "backspace"],
    "linux/log/packagemanager": [
        "package_manager",
        "operation",
        "package_name",
        "command",
        "requested_by_user",
    ],
    "linux/log/journal": ["Message", "Cmdline"],
    "application/openssh/authorized_keys": [
        "Key_Type",
        "public_Key",
        "Comment",
        "Options",
        "Path",
    ],
    "application/openssh/known_host": [
        "Hostname_Pattern",
        "Key_Type",
        "Public_Key",
        "Comment",
        "Marker",
        "Path",
    ],
    "application/openssh/private_key": [
        "Key_Format",
        "Key_Type",
        "Public_Key",
        "Comment",
        "Encrypted",
    ],
    "application/openssh/public_key": [
        "Key_Type",
        "Public_Key",
        "Comment",
    ],
    "linux/shadow": ["Name"],
    "linux/history": ["Command", "Source"],
    "linux/iptables/save": ["Type", "Table", "Chain", "Program", "rule"],
    "linux/debian/dpkg/package/log": [
        "Name",
        "Operation",
        "Status",
        "Version_Old",
        "Version",
    ],
    "linux/debian/dpkg/package/status": [
        "Name",
        "Status",
        "Priority",
        "Section",
        "Version",
    ],
    "linux/log/audit": ["message"],
    "linux/log/auth": ["message"],
    "linux/log/wtmp": [
        "UT_Type",
        "UT_User",
        "UT_Pid",
        "UT_Line",
        "UT_ID",
        "UT_Host",
        "UT_Addr",
    ],
    "linux/log/btmp": [
        "UT_Type",
        "UT_User",
        "UT_Pid",
        "UT_Line",
        "UT_ID",
        "UT_Host",
        "UT_Addr",
    ],
    "linux/log/messages": ["Message"],
    "linux/log/atop": [
        "Process",
        "CMDline",
    ],
    "linux/log/lastlog": ["UID", "UT_User", "UT_Host", "UT_Tty"],
    "windows/user": ["name", "home", "SID"],
    "windows/filesystem/recyclebin": ["Path", "Deleted_Path"],
    "windows/service": ["Name", "DisplayName", "ImagePath", "Start", "Type"],
    "uri_datetime": ["Example"],
    "path_datetime": ["Path"],
    "windows/pathext": ["Pathext"],
    "windows/environment": ["Name", "Value"],
    "filesystem/acquire_open_handles": ["Name", "Handle_Type", "Object"],
    "filesystem/windows/iis/logs": [
        "Client_IP",
        "Server_IP",
        "Site_Name",
        "Request_Method",
        "Request_Path",
        "Request_Query",
        "Request_Size_Bytes",
        "Response_Size_Bytes",
        "Service_Status_Code",
        "Win32_Status_Code",
    ],
    "filesystem/windows/powershell/history": ["Command"],
    "filesystem/windows/defender/evtx": [
        "EventID",
        "Provider_Name",
        "Process_Name",
        "Threat_Name",
    ],
    "filesystem/windows/defender/quarantine/behavior": [
        "Detection_Type",
        "Detection_Name",
    ],
    "filesystem/windows/defender/quarantine": ["Detection_Type", "Detection_Name"],
    "filesystem/windows/defender/exclusion": ["type", "value"],
    "filesystem/windows/defender/quarantine/file": ["Detection_Name", "Detection_Path"],
    "windows/catroot": ["Hint", "Source"],
    "windows/thumbcache/iconcache": ["Path"],
    "windows/thumbcache/thumbcache": ["Path"],
    "windows/thumbcache/index": ["Path"],
    "windows/syscache/object": ["Program_ID", "File_ID", "Path"],
    "windows/registry/appxdebug/key": ["Name", "Debug_Info"],
    "filesystem/registry/bootshell": ["Path"],
    "filesystem/registry/appinit": ["Path"],
    "filesystem/registry/winrar": ["Path"],
    "filesystem/registry/filerenameoperations": ["Path"],
    "filesystem/registry/ndis": ["Network", "Name"],
    "filesystem/registry/commandprocautorun": ["Path"],
    "filesystem/registry/nullsessionpipes": ["Name"],
    "filesystem/registry/knowndlls": ["Path"],
    "filesystem/registry/winsocknamespaceprovider": ["LibraryPath"],
    "filesystem/registry/alternateshell": ["Path"],
    "filesystem/registry/sessionmanager": ["Path"],
    "windows/activitiescache": ["App_ID"],
    "path_string_datetime": ["String"],
    "filesystem/windows/startupinfo": ["Path", "Commandline", "Parent_Name"],
    "windows/keyboard": ["Layout", "ID"],
    "windows/filesystem/lnk": ["LNK_Name", "LNK_IconLocation", "LNK_Path"],
    "filesystem/windows/ual/virtual_machines": ["Path"],
    "filesystem/windows/ual/client_access": [
        "Authenticated_User",
        "Client_name",
        "Address",
        "Access_Count",
        "Total_Access_Count",
    ],
    "filesystem/windows/ual/system_identity": [
        "System_DNS_Hostname",
        "System_Domain_Name",
        "System_Manufacturer",
        "System_Product_Name",
    ],
    "filesystem/windows/ual/role_access": ["Role_Name", "Product_Name"],
    "filesystem/ntfs/prefetch": ["FileName", "RunCount"],
    "filesystem/windows/cim/consumerbinding": ["Query"],
    "windows/notification/wpndatabase/handler": ["ID", "Primary_ID"],
    "windows/notification/wpndatabase": ["ID"],
    "windows/adpolicy": ["GUID", "Key", "Value", "Path"],
    "filesystem/windows/clfs": ["Stream_Name", "Stream_ID", "Container_Name"],
    "windows/registry/sam": ["Fullname", "Username", "AdminComment"],
    "windows/appcompat/InventoryApplicationFile": ["Name", "Product_Name", "Path"],
    "windows/appcompat/InventoryApplication": [
        "Name",
        "Registry_Key_Path",
    ],
    "windows/appcompat/DeviceContainer": ["Manufacturer", "Model_Name"],
    "windows/appcompat/file": ["Product_Name", "Company_Name", "Path"],
    "windows/appcompat/programs": ["Name", "Publisher", "Path"],
    "windows/appcompat/ApplicationShortcut": ["Path"],
    "windows/appcompat/InventoryDriverBinary": ["Driver_Name", "Product", "Service"],
    "windows/appcompat/AppLaunch": ["Path"],
    "filesystem/windows/sru/energy_usage": ["App", "User"],
    "filesystem/windows/sru/push_notification": ["App", "User"],
    "filesystem/windows/sru/application_timeline": ["App", "User"],
    "filesystem/windows/sru/sdp_cpu_provider": ["App", "User", "Processor_Time"],
    "filesystem/windows/sru/sdp_network_provider": [
        "App",
        "User",
        "Bytes_Inbound",
        "Bytes_Outbound",
    ],
    "filesystem/windows/sru/energy_usage_lt": ["App", "User"],
    "filesystem/windows/sru/sdp_volume_provider": ["App", "User", "Total", "Used"],
    "filesystem/windows/sru/network_data": ["App", "User", "Bytes_Sent", "Bytes_Recvd"],
    "filesystem/windows/sru/energy_estimator": ["App", "User"],
    "filesystem/windows/sru/sdp_physical_disk_provider": [
        "App",
        "User",
        "Size_In_Bytes",
    ],
    "filesystem/windows/sru/network_connectivity": [
        "App",
        "User",
        "Connected_Time",
        "Connect_Start_Time",
    ],
    "filesystem/windows/sru/application": ["App", "User"],
    "filesystem/windows/sru/vfu": ["App", "User", "Start_Time", "End_Time"],
    "windows/registry/regf/value": ["Path", "Key", "Name"],
    "windows/registry/regf/key": ["Path", "Key"],
    "windows/shellbag": ["Path"],
    "windows/registry/run": ["Name", "Path", "Key"],
    "windows/registry/nethist": [
        "Profile_Name",
        "Description",
        "DNS_Suffix",
        "First_Network",
    ],
    "uri": ["Example"],
    "windows/registry/bam": ["Path"],
    "windows/registry/auditpol": ["Name", "Value", "Category"],
    "windows/recentfilecache": ["Path"],
    "windows/registry/clsid": ["Name", "Value", "ClsID"],
    "windows/registry/cit/system/bitmap/input": [
        "Aggregation_Period_In_S",
        "Bit_Period_In_S",
    ],
    "windows/registry/cit/system/bitmap/nput_touch": [
        "Aggregation_Period_In_S",
        "Bit_Period_In_S",
    ],
    "windows/registry/cit/system/bitmap/foreground": [
        "Aggregation_Period_In_S",
        "Bit_Period_In_S",
    ],
    "windows/registry/cit/system/bitmap/display_power": [
        "Aggregation_Period_In_S",
        "Bit_Period_In_S",
    ],
    "windows/registry/cit/system/bitmap/display_request_change": [
        "Aggregation_Period_In_S",
        "Bit_Period_In_S",
    ],
    "windows/registry/cit/program": ["Path", "Command_Line"],
    "windows/registry/cit/dp": ["Update_Key"],
    "windows/registry/cit/system": ["Aggregation_Period_In_S"],
    "windows/registry/cit/module": ["Tracked_Module", "Executable"],
    "windows/registry/cit/puu": ["Update_Key"],
    "windows/registry/cit/dp/duration": ["Application", "Duration"],
    "windows/registry/cit/telemetry": ["Path", "Version", "Value"],
    "windows/registry/cit/system/bitmap/unknown": [
        "Aggregation_Period_In_S",
        "Bit_Period_In_S",
    ],
    "windows/registry/mru/recentdocs": ["Value"],
    "windows/registry/mru/msoffice": ["Value"],
    "windows/registry/mru/mapnetworkdrive": ["Value"],
    "windows/registry/mru/opensave": ["Value"],
    "windows/registry/mru/run": ["Value"],
    "windows/registry/mru/acmru": ["Value"],
    "windows/registry/mru/lastvisited": ["FileName", "Key", "Path"],
    "windows/registry/mru/mstsc": ["Value"],
    "windows/registry/sevenzip/archistory": ["Path"],
    "windows/registry/sevenzip/copyhistory": ["Path"],
    "windows/registry/sevenzip/folderhistory": ["Path"],
    "windows/registry/sevenzip/pathhistory": ["Path"],
    "windows/registry/sevenzip/panelpath": ["Path"],
    "windows/registry/muicache": ["Value", "Name", "Path"],
    "windows/registry/trusteddocuments": ["Application", "Type", "Document_Path"],
    "windows/registry/userassist": ["Path", "Number_Of_Executions"],
    "windows/shimcache": ["Path", "Index"],
    "windows/registry/usb": ["FriendlyName"],
    "filesystem/windows/evt": ["EventID", "SourceName"],
    "filesystem/windows/pfro": ["Operation", "Path"],
    "application/log/remoteaccess": ["Tool", "Description"],
    "application/av/mcafee/msc/log": [
        "Threat",
        "Message",
        "Keywords",
    ],
    "application/av/mcafee/msc/firewall": [
        "IPAddress",
        "Port",
        "Protocol",
        "Message",
        "Keywords",
    ],
    "application/av/trendmicro/wf/firewall": [
        "Local_IP",
        "Remote_IP",
        "Direction",
        "Port",
        "Path",
        "Description",
    ],
    "application/av/trendmicro/wf/log": ["Threat", "Path"],
    "application/av/sophos/hitman/log": ["Alert", "Description", "Details"],
    "application/av/sophos/home/log": ["Description", "Path"],
    "application/log/cpanel/lastlogin": ["User", "Remote_IP"],
    "application/vpn/openvpn/client": ["Name"],
    "application/vpn/openvpn/server": ["Name"],
    "powershell/history": ["Command", "Source"],
    "apps/containers/docker/container": ["Container_ID", "Image", "Command"],
    "apps/containers/docker/image": ["Name", "Tag"],
    "application/vpn/wireguard/interface": ["Name"],
    "application/vpn/wireguard/peer": ["Name"],
    "datetime": ["Example"],
    "osx/account_policy": ["Username", "Failed_Login_Count"],
}

skip_record_names = ["uri_datetime", "uri", "datetime"]
timesketch_fields = [
    "message",
    "data_type",
    "timestamp",
    "datetime",
    "timestamp_desc",
]
# FIX usage of the message field
# logstash_fields = ["data_type", "event", "log", "host"]

for p in plugin.plugins():
    if len(p["exports"]):
        loaded_plugin = plugin.load(p)
        all_records = loaded_plugin.get_all_records.__record__
        if all_records:
            for r in all_records:
                if not plugin_fields.get(r.name):
                    print("--------------------------")
                    print(f"Record {r.name} is empty")
                    print("--------------------------")
                    exit()
                if not plugin_fields.get(r.name) and not r.name in skip_record_names:
                    print(f"The record {r.name} is new")
                    exit()
                if r.name in skip_record_names:
                    continue
                print(f'  else if [data_type] == "{r.name}" {{')
                message = ""
                for field in plugin_fields.get(r.name):
                    if not field.lower() in list(map(str.lower, r.fields)):
                        print("--------------------------")
                        print(r.fields)
                        print(f"Field {field} is not part of the the record {r.name}")
                        print("--------------------------")
                        exit()
                    if not field:
                        print("--------------------------")
                        print(f"Field {field} is empty in the record {r.name}")
                        print("--------------------------")
                        exit()
                    message += f"{field.capitalize()}: %{{{field.lower()}}} "
                message = message[:-1]
                print(f'    mutate {{ add_field => {{ "message" => "{message}" }} }}')
                print("  }")
