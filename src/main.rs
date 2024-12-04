use core::str;
use std::collections::HashMap;
use std::env;
use std::process::Command;
use std::{io, vec};
use sysinfo::{NetworkData, Networks, System};
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::{self, RegKey};
fn main() {
    let args: Vec<String> = env::args().collect();
    for (_, arg) in args.iter().enumerate() {
        match arg.as_str() {
            "get_hostname" => {
                println!("{}\n", get_hostname())
            }
            "get_os_short" => {
                println!("{}\n", get_os(true))
            }
            "get_os" => {
                println!("{}\n", get_os(false))
            }
            "get_cpu_short" => {
                println!("{}\n", get_cpu(true))
            }
            "get_cpu" => {
                println!("{}\n", get_cpu(false))
            }
            "get_mb_short" => {
                println!("{}\n", get_mb(true))
            }
            "get_mb" => {
                println!("{}\n", get_mb(false))
            }
            "get_ram_short" => {
                println!("{}\n", get_ram(true))
            }
            "get_ram" => {
                println!("{}\n", get_ram(false))
            }
            "get_disks" => {
                println!("{}\n", get_disks())
            }
            "get_partitions" => {
                println!("{}\n", get_partitions())
            }
            "get_networks" => {
                println!("{}\n", get_networks())
            }
            "get_processes" => {
                println!("{}\n", get_processes())
            }
            "get_serial" => {
                println!("{}\n", get_serial())
            }
            "get_mb_serial" => {
                println!("{}\n", get_mb_serial())
            }
            "get_mac_1" => {
                println!("{}\n", get_mac(0))
            }
            "get_mac_2" => {
                println!("{}\n", get_mac(1))
            }
            "get_hw_short" => {
                println!("{}, {}, {}\n", get_mb(true), get_cpu(true), get_ram(true))
            }
            "get_installed_programs" => {
                println!("{}\n", get_programs())
            }
            "get_hw" => {
                println!(
                    "{}\nSerial:\n{}\n{}\n{}\n{}\n{}\n{}\n",
                    get_mb(false),
                    get_serial(),
                    get_cpu(false),
                    get_ram(false),
                    get_disks(),
                    get_partitions(),
                    get_networks()
                )
            }
            _ => {}
        }
    }
    return;
}
fn get_hostname() -> String {
    let os_full_info = get_os_info();
    format!("{}", os_full_info[0]["CSName"])
}
fn get_os(short: bool) -> String {
    let os_full_info = get_os_info();

    let mut key = String::default();
    if get_windows_key().is_ok() {
        key = get_windows_key().unwrap().to_string();
    }
    if short {
        format!(
            "{} {} Build: {}",
            os_full_info[0]["Caption"],
            os_full_info[0]["OSArchitecture"],
            os_full_info[0]["BuildNumber"],
        )
    } else {
        let os = get_os_info();
        format!("OS:\nFornecedor do OS: {}, Versão: {}, Build: {}, Arquitetura: {}, HD de Inicialização: {}, Caminho da Instalação: {}, Serial: {}",
                  os[0]["Manufacturer"],
                  os[0]["Caption"],
                  os[0]["BuildNumber"],
                  os[0]["OSArchitecture"],
                  os[0]["BootDevice"],
                  os[0]["SystemDirectory"],
                  key
    )
    }
}
fn get_cpu(short: bool) -> String {
    let sys = System::new_all();
    if short {
        format!(
            "{} {} Threads {} MHz",
            sys.cpus()[0].brand().trim(),
            sys.cpus().len(),
            sys.cpus()[0].frequency()
        )
    } else {
        let mut sys = System::new_all();
        sys.refresh_cpu_usage(); // Refreshing CPU usage.
        let mut cpu_info = String::default();
        let mut threads_info = String::default();
        cpu_info += &format!(
            "CPU: {} Fabricante: {}, Threads: {}, Uso: {:.2}%\n",
            sys.cpus()[0].brand().trim(),
            sys.cpus()[0].vendor_id().trim(),
            sys.cpus().len(),
            sys.global_cpu_usage()
        );
        //println!("=> Dados dos Threads:");
        // Tempo para obter o uso da CPU
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        for cpu in sys.cpus() {
            threads_info += &format!(
                "{}, Frequência: {} MHz, Uso: {:.2}%\n",
                cpu.name().replace("CPU", "Thread"),
                cpu.frequency(),
                cpu.cpu_usage()
            );
        }
        // Tempo para obter o uso da CPU Novamente
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);

        format!(
            "CPU:\n{}Informação dos Threads:\n{}",
            cpu_info, threads_info
        )
    }
}
fn get_mb(short: bool) -> String {
    let mb_info = get_mb_info();
    let mut base_board_info = String::default();
    if short {
        for mb in mb_info {
            base_board_info = format!("{} {}", mb["Manufacturer"], mb["Product"]);
        }
    } else {
        base_board_info += "Placa Mãe:\n";
        for mb in mb_info {
            base_board_info += &format!(
                "Fabricante: {}, Modelo: {}, Serial/Tag: {}",
                mb["Manufacturer"], mb["Product"], mb["SerialNumber"]
            );
        }
    }
    base_board_info
}
fn get_ram(short: bool) -> String {
    let mem_data_lines = get_memory_data();
    let mut total_ram: f64 = 0.0;
    if short {
        for i in 0..mem_data_lines.len() {
            let mem_data = mem_data_lines[i].clone();
            let mem_size_bytes = mem_data["Capacity"].parse::<f64>().unwrap();

            total_ram += mem_size_bytes.clone() / 1024.0 / 1024.0 / 1024.0;
        }
        format!("{:.3} GB RAM", total_ram)
    } else {
        let sys = System::new_all();
        let ram_info = format!(
            "Total: {} MB, Em Uso: {} MB, Páginada Total: {} MB, Páginada em Uso: {} MB",
            sys.total_memory() / 1024 / 1024,
            sys.used_memory() / 1024 / 1024,
            sys.total_swap() / 1024 / 1024,
            sys.used_swap() / 1024 / 1024
        );

        // Dados da Memória física
        //println!("=> Dados físicos da Memória");
        let mem_data_lines = get_memory_data();
        let mut physical_memory_info = String::default();
        for i in 0..mem_data_lines.len() {
            let mem_data = mem_data_lines[i].clone();
            let mem_size = mem_data["Capacity"].parse::<u128>();
            physical_memory_info += &format!("Posição: {}, Capacidade: {} MB, Velocidade: {} MHz, Fabricante: {}, Modelo: {}, Serial: {}\n",
                                             mem_data["BankLabel"],
                                             mem_size.unwrap() / 1024 / 1024,
                                             mem_data["Speed"],
                                             mem_data["Manufacturer"],
                                             mem_data["PartNumber"].trim(),
                                             mem_data["SerialNumber"]
            );
        }
        format!(
            "Memória Operacional:\n{}\nMemória Física:\n{}",
            ram_info, physical_memory_info
        )
    }
}
fn get_serial() -> String {
    let mb_info = get_bios_info();

    let mut serial_info = String::default();
    for mb in mb_info {
        serial_info = mb["SerialNumber"].clone();
    }
    serial_info
}
fn get_mb_serial() -> String {
    let mb_info = get_mb_info();

    let mut serial_info = String::default();
    for mb in mb_info {
        serial_info = mb["SerialNumber"].clone();
    }
    serial_info
}
fn get_networks() -> String {
    let mut network_info: String = "Rede:\n".to_string();
    let network_data = get_network_data();
    let network_config = get_network_config();
    let mut networks = Networks::new_with_refreshed_list();

    networks.refresh();

    let mut net_data: Vec<&NetworkData> = vec![];
    for (_, data) in &networks {
        net_data.push(data);
    }

    for adapter in network_data {
        let data = net_data.iter().find(|x| {
            x.mac_address()
                .to_string()
                .to_uppercase()
                .eq(&adapter["MACAddress"])
        });

        let config = network_config
            .iter()
            .find(|x| x["MACAddress"].eq(&adapter["MACAddress"]));

        if data.is_some() {
            let speed_conf = adapter["Speed"].parse::<u128>();
            let speed: u128;
            if speed_conf.is_ok() {
                speed = speed_conf.unwrap();
            } else {
                speed = 0;
            }
            let mut addrs: Vec<String> = vec![];
            for ip in data.unwrap().ip_networks() {
                addrs.push(ip.addr.to_string());
            }
            network_info += &format!(
                "Modelo: {}:, Identificação: {}, Endereços de IP: {:?}, Máscara: {}, Gateway: {}, DNSs: {}, Endereço MAC: {}, Velocidade: {} MB, Download: {} MB, Upload: {} MB, Estado: Conectado\n",
                adapter["ProductName"],
                adapter["NetConnectionID"],
                config.unwrap()["IPAddress"],
                config.unwrap()["IPSubnet"],
                config.unwrap()["DefaultIPGateway"],
                config.unwrap()["DNSServerSearchOrder"],
                adapter["MACAddress"],
                speed / 1000 / 1000,
                data.unwrap().total_received() / 1024 / 1024,
                data.unwrap().total_transmitted() / 1024 / 1024,
            );
        } else {
            network_info += &format!(
                "Modelo: {}:, Identificação: {}, Estado: Desconectado/Desativado\n",
                adapter["NetConnectionID"], adapter["ProductName"],
            );
        }
    }
    network_info
}
fn get_mac(index: usize) -> String {
    let network_data = get_gateway_mac_ip_mask_dhcp_dns();
    let mut i: usize = 0;
    let mut network_info: String = String::default();
    for data in network_data {
        if i == index {
            network_info = data["MACAddress"].to_string();
            break;
        }
        i += 1;
    }
    network_info
}
fn get_disks() -> String {
    let mut disk_info: String = "Discos:\n".to_string();
    let disks = get_disks_data();
    for disk in &disks {
        let disk_size = disk["Size"].parse::<f32>();
        disk_info += &format!(
            "Identificação: {:?}, Local: {:?}, Modelo: {:?}, Tamanho: {:.2} GB, Firmware {:?}, Serial {:?}\n",
            disk["Index"],
            disk["Name"],
            disk["Model"],
            disk_size.unwrap() / 1024.0 / 1024.0 / 1024.0,
            disk["FirmwareRevision"],
            disk["SerialNumber"],
        );
    }
    disk_info
}
fn get_partitions() -> String {
    let mut partitions_info: String = "Partições:\n".to_string();
    let parts = get_partition_info();

    for part in &parts {
        let free = part["FreeSpace"].parse::<f32>();
        let total = part["Size"].parse::<f32>();
        let offset = part["StartingOffset"].parse::<f32>();
        if free.is_ok() {
            partitions_info += &format!("Disco: {}, Letra: {:?}, Formato: {:?}, Espaço Livre: {:.2} GB, Espaço Total: {:.2} GB, Offset: {:.2} GB\n",
                     part["DiskIndex"],
                     part["DeviceID"],
                     part["FileSystem"],
                     free.unwrap() / 1024.0 / 1024.0 / 1024.0,
                     total.unwrap() / 1024.0 / 1024.0 / 1024.0,
                     offset.unwrap() / 1024.0 / 1024.0 / 1024.0);
        } else {
            partitions_info += &format!(
                "Disco: {}, Espaço Total: {:.2} GB, Offset: {:.2} GB, Não Montada\n",
                part["DiskIndex"],
                total.unwrap() / 1024.0 / 1024.0 / 1024.0,
                offset.unwrap() / 1024.0 / 1024.0 / 1024.0
            );
        }
    }
    partitions_info
}
fn get_processes() -> String {
    println!("Processos:\n");
    let mut process_info: String = String::default();
    let process = get_process_info();
    for proc in process {
        process_info += &format!(
            "Nome: {:?}, PID: {:?}, Uso de CPU: {:.2} %, Uso de Memória: {:?} MB, Uso do Disco: {:?} MB, Caminho: {:?}, Tempo em Execução {:?}\n",
            proc["Name"],
            proc["PID"],
            proc["CPU"],
            proc["Memory"],
            proc["Disk"],
            proc["Path"],
            proc["Runtime"])
    }
    process_info
}
fn get_programs() -> String {
    let mut program_info: String = "Programas Instalados:\n".to_string();
    let programs = get_installed_programs();
    for program in &programs {
        program_info += &format!(
            "Nome: {:?}, Desenvolvedor: {:?}, Local: {:?}, Versão: {:?}, Data de Instalação: {:?}\n",
            program["Name"],
            program["Vendor"],
            program["InstallLocation"],
            program["Version"],
            program["InstallDate"],
        );
    }
    program_info
}
fn get_mb_info() -> Vec<HashMap<String, String>> {
    // Executa o comando WMIC para obter as informações das memórias
    let output = Command::new("wmic")
        .arg("baseboard")
        .arg("get")
        .arg("Manufacturer,Product,SerialNumber")
        .arg("/format:list")
        .output()
        .expect("Falha ao executar o comando WMIC");

    // Converte a saída para uma string
    let output_str = str::from_utf8(&output.stdout).expect("Falha ao converter saída");
    // Divide as linhas da saída
    let lines = output_str.lines();
    let data = to_hashmap(lines, "SerialNumber");
    data
}
fn get_bios_info() -> Vec<HashMap<String, String>> {
    // Executa o comando WMIC para obter as informações das memórias
    let output = Command::new("wmic")
        .arg("bios")
        .arg("get")
        .arg("BIOSVersion,Manufacturer,SerialNumber")
        .arg("/format:list")
        .output()
        .expect("Falha ao executar o comando WMIC");

    // Converte a saída para uma string
    let output_str = str::from_utf8(&output.stdout).expect("Falha ao converter saída");
    // Divide as linhas da saída
    let lines = output_str.lines();
    let data = to_hashmap(lines, "SerialNumber");
    data
}
fn get_os_info() -> Vec<HashMap<String, String>> {
    // Executa o comando WMIC para obter as informações das memórias
    let output = Command::new("wmic")
        .arg("os")
        .arg("get")
        .arg("Caption,BuildNumber,BootDevice,InstallDate,CSName,LastBootUpTime,OSArchitecture,SerialNumber,SystemDirectory,Version,CurrentTimeZone,CurrentTimeZone,Manufacturer")
        .arg("/format:list")
        .output()
        .expect("Falha ao executar o comando WMIC");

    // Converte a saída para uma string
    let output_str = str::from_utf8(&output.stdout).expect("Falha ao converter saída");

    // Divide as linhas da saída
    let mut lines = output_str.lines();

    // Ignora a primeira linha (cabeçalho)
    let header = lines.next();

    // Verifica se há cabeçalho e dados válidos
    if header.is_none() {
        println!("Nenhum dado encontrado.");
        return vec![];
    }
    // Converte a saída para uma string
    let output_str = str::from_utf8(&output.stdout).expect("Falha ao converter saída");
    // Divide as linhas da saída
    let lines = output_str.lines();
    let data = to_hashmap(lines, "Version");
    data
}
fn get_windows_key() -> io::Result<String> {
    let hklm = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    let key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform";
    let subkey = hklm.open_subkey(key_path)?;
    let product_key: String = subkey.get_value("BackupProductKeyDefault")?;
    Ok(product_key)
}
fn get_disks_data() -> Vec<HashMap<String, String>> {
    // Executa o comando WMIC para obter as informações das memórias
    let output = Command::new("wmic")
        .arg("diskdrive")
        .arg("get")
        .arg("name,model,size,FirmwareRevision,SerialNumber,index")
        .arg("/format:list")
        .output()
        .expect("Falha ao executar o comando WMIC");

    // Converte a saída para uma string
    let output_str = str::from_utf8(&output.stdout).expect("Falha ao converter saída");

    // Divide as linhas da saída
    let lines = output_str.lines();

    // Processa as linhas restanteslet lines = output_str.lines();
    let data = to_hashmap(lines, "Size");
    data
}
fn get_partition_info() -> Vec<HashMap<String, String>> {
    // Executa o comando WMIC para obter as informações das memórias
    let output = Command::new("wmic")
        .arg("partition")
        .arg("get")
        .arg("BootPartition,DiskIndex,Index,Size,StartingOffset")
        .arg("/format:list")
        .output()
        .expect("Falha ao executar o comando WMIC");

    // Converte a saída para uma string
    let output_str = str::from_utf8(&output.stdout).expect("Falha ao converter saída");
    // Divide as linhas da saída
    let lines = output_str.lines();

    let partition = to_hashmap(lines, "StartingOffset");

    let mounted_partition = get_mounted_partitions();
    let linked = get_paritition_linked_logical_disk();
    let mut full_data: Vec<HashMap<String, String>> = vec![];
    for entry in linked {
        if let Some((disk_index, partition_index, drive_letter)) =
            extract_disk_partition_and_drive(&entry)
        {
            let part = partition.iter().find(|x| {
                x["DiskIndex"] == disk_index.to_string()
                    && x["Index"] == partition_index.to_string()
            });
            let log = mounted_partition
                .iter()
                .find(|x| x["DeviceID"] == drive_letter);
            if part.is_none() {
                println!(
                    "Part None, Disk Index: {:?}, Part Index {:?}",
                    disk_index, partition_index
                );
            }
            if part.is_some() && log.is_some() {
                let mut p_data: HashMap<String, String> = HashMap::new();
                for p in part.unwrap() {
                    p_data.insert(p.0.to_string(), p.1.to_string());
                }
                for l in log.unwrap() {
                    p_data.insert(l.0.to_string(), l.1.to_string());
                }
                full_data.push(p_data);
            }
        } else {
            println!("Falha ao processar: {:?}", entry);
        }
    }
    for part in partition {
        let p_data = full_data
            .iter()
            .find(|x| x["DiskIndex"] == part["DiskIndex"] && x["Index"] == part["Index"]);
        if p_data.is_none() {
            let mut p_data: HashMap<String, String> = HashMap::new();
            for p in part {
                p_data.insert(p.0.to_string(), p.1.to_string());
            }

            p_data.insert("DeviceID".to_string(), "?".to_string());
            p_data.insert("FileSystem".to_string(), "?".to_string());
            p_data.insert("FreeSpace".to_string(), "?".to_string());
            p_data.insert("VolumeSerialNumber".to_string(), "?".to_string());
            full_data.push(p_data);
        }
    }
    // Retorna as linhas processadas
    full_data
}
fn get_installed_programs() -> Vec<HashMap<String, String>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let uninstall = hklm.open_subkey_with_flags(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        KEY_READ,
    );

    let mut software_list = Vec::new();

    for item in uninstall.as_ref().unwrap().enum_keys() {
        if let Ok(subkey_name) = item {
            let subkey = uninstall
                .as_ref()
                .unwrap()
                .open_subkey_with_flags(&subkey_name, KEY_READ);
            let name: Option<String> = subkey.as_ref().unwrap().get_value("DisplayName").ok();
            let version: Option<String> = subkey.as_ref().unwrap().get_value("DisplayVersion").ok();
            let vendor: Option<String> = subkey.as_ref().unwrap().get_value("Publisher").ok();
            let install_date: Option<String> =
                subkey.as_ref().unwrap().get_value("InstallDate").ok();
            let install_location: Option<String> =
                subkey.as_ref().unwrap().get_value("InstallLocation").ok();

            if let Some(name) = name {
                let mut data = HashMap::new();
                data.insert("Name".to_string(), name);
                if let Some(version) = version {
                    data.insert("Version".to_string(), version);
                } else {
                    data.insert("Version".to_string(), String::default());
                }
                if let Some(vendor) = vendor {
                    data.insert("Vendor".to_string(), vendor);
                } else {
                    data.insert("Vendor".to_string(), String::default());
                }
                if let Some(install_date) = install_date {
                    data.insert("InstallDate".to_string(), install_date);
                } else {
                    data.insert("InstallDate".to_string(), String::default());
                }
                if let Some(install_location) = install_location {
                    data.insert("InstallLocation".to_string(), install_location);
                } else {
                    data.insert("InstallLocation".to_string(), String::default());
                }
                software_list.push(data);
            }
        }
    }
    software_list
}

fn get_mounted_partitions() -> Vec<HashMap<String, String>> {
    // Executa o comando WMIC para obter as informações das memórias
    let output = Command::new("wmic")
        .arg("logicaldisk")
        .arg("get")
        .arg("DeviceID,FileSystem,FreeSpace,Size,VolumeSerialNumber")
        .arg("/format:list")
        .output()
        .expect("Falha ao executar o comando WMIC");

    // Converte a saída para uma string
    let output_str = str::from_utf8(&output.stdout).expect("Falha ao converter saída");
    // Divide as linhas da saída
    let lines = output_str.lines();
    let data = to_hashmap(lines, "VolumeSerialNumber");
    data
}
fn get_paritition_linked_logical_disk() -> Vec<HashMap<String, String>> {
    // Executa o comando WMIC para obter as informações das memórias
    let output = Command::new("wmic")
        .arg("path")
        .arg("Win32_LogicalDiskToPartition")
        .arg("get")
        .arg("Antecedent,Dependent")
        .arg("/format:list")
        .output()
        .expect("Falha ao executar o comando WMIC");

    // Converte a saída para uma string
    let output_str = str::from_utf8(&output.stdout).expect("Falha ao converter saída");
    // Divide as linhas da saída
    let lines = output_str.lines();
    let data = to_hashmap(lines, "Dependent");
    data
}
fn extract_disk_partition_and_drive(entry: &HashMap<String, String>) -> Option<(u32, u32, String)> {
    let disk_pattern = "Disk #";
    let partition_pattern = "Partition #";
    let drive_pattern = "Win32_LogicalDisk.DeviceID\"";
    let drive_pattern_alt = "Win32_LogicalDisk.DeviceID=\"";
    //println!("Entry: {:?}", entry);
    if entry.keys().len() >= 2 {
        let antecedent = &entry["Antecedent"];
        let dependent = &entry["Dependent"];

        // Extrai DiskIndex e PartitionIndex do Antecedent
        if let Some(disk_start) = antecedent.find(disk_pattern) {
            let disk_index_start = disk_start + disk_pattern.len();
            if let Some(partition_start) = antecedent.find(partition_pattern) {
                let partition_index_start = partition_start + partition_pattern.len();

                let disk_index = antecedent[disk_index_start..]
                    .split(',')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .parse::<u32>()
                    .ok()?;

                let partition_index = antecedent[partition_index_start..]
                    .split('"')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .parse::<u32>()
                    .ok()?;

                // Extrai a letra da unidade lógica do Dependent
                if let Some(drive_start) = dependent.find(drive_pattern) {
                    let drive_letter_start = drive_start + drive_pattern.len();
                    let drive_letter = dependent[drive_letter_start..]
                        .split('"')
                        .next()
                        .unwrap_or("")
                        .to_string();

                    return Some((disk_index, partition_index, drive_letter));
                } else if let Some(drive_start) = dependent.find(drive_pattern_alt) {
                    let drive_letter_start = drive_start + drive_pattern_alt.len();
                    let drive_letter = dependent[drive_letter_start..]
                        .split('"')
                        .next()
                        .unwrap_or("")
                        .to_string();

                    return Some((disk_index, partition_index, drive_letter));
                }
            }
        }
    }
    None
}
fn get_memory_data() -> Vec<HashMap<String, String>> {
    // Executa o comando WMIC para obter as informações das memórias
    let output = Command::new("wmic")
        .arg("memorychip")
        .arg("get")
        .arg("Capacity,Speed,Manufacturer,PartNumber,BankLabel,SerialNumber")
        .arg("/format:list")
        .output()
        .expect("Falha ao executar o comando WMIC");

    // Converte a saída para uma string
    let output_str = str::from_utf8(&output.stdout).expect("Falha ao converter saída");
    // Divide as linhas da saída
    let lines = output_str.lines();
    let data = to_hashmap(lines, "Speed");
    data
}
fn get_network_data() -> Vec<HashMap<String, String>> {
    let filter = format!("PhysicalAdapter={}", true);
    // Executa o comando WMIC para obter as informações das memórias
    let output = Command::new("wmic")
        .arg("nic")
        .arg("where")
        .arg(&filter)
        .arg("get")
        .arg("speed,manufacturer,ProductName,NetConnectionID,MACAddress")
        .arg("/format:list")
        .output()
        .expect("Falha ao executar o comando WMIC");

    // Converte a saída para uma string
    let output_str = str::from_utf8(&output.stdout).expect("Falha ao converter saída");
    // Divide as linhas da saída
    let lines = output_str.lines();
    let data = to_hashmap(lines, "Speed");
    data
}
fn get_network_config() -> Vec<HashMap<String, String>> {
    let filter = format!("IPEnabled={}", true);
    // Executa o comando WMIC para obter as informações das memórias
    let output = Command::new("wmic")
        .arg("nicconfig")
        .arg("where")
        .arg(&filter)
        .arg("get")
        .arg("DefaultIPGateway,DHCPServer,DNSServerSearchOrder,IPAddress,IPSubnet,MACAddress")
        .arg("/format:list")
        .output()
        .expect("Falha ao executar o comando WMIC");

    // Converte a saída para uma string
    let output_str = str::from_utf8(&output.stdout).expect("Falha ao converter saída");
    // Divide as linhas da saída
    let lines = output_str.lines();
    let data = to_hashmap(lines, "MACAddress");
    data
}
fn get_gateway_mac_ip_mask_dhcp_dns() -> Vec<HashMap<String, String>> {
    let filter = format!("IPEnabled={}", true);
    // Executa o comando WMIC para obter as informações das memórias
    let output = Command::new("wmic")
        .arg("nicconfig")
        .arg("where")
        .arg(&filter)
        .arg("get")
        .arg("DefaultIPGateway,DHCPServer,DNSServerSearchOrder,IPAddress,IPSubnet,MACAddress")
        .arg("/format:list")
        .output()
        .expect("Falha ao executar o comando WMIC");

    // Converte a saída para uma string
    let output_str = str::from_utf8(&output.stdout).expect("Falha ao converter saída");
    // Divide as linhas da saída
    let lines = output_str.lines();
    let data = to_hashmap(lines, "MACAddress");
    data
}
fn get_process_info() -> Vec<HashMap<String, String>> {
    let mut procs: Vec<HashMap<String, String>> = vec![];
    let sys = System::new_all();
    for (pid, process) in sys.processes() {
        let exe: String;
        if process.exe() != None {
            exe = process.exe().unwrap().to_str().unwrap().to_string()
        } else {
            exe = "Internal".to_string()
        }
        let runtime: String;
        if process.run_time() > 24 * 60 * 60 {
            runtime = (process.run_time() / 24 / 60 / 60).to_string() + " Dias";
        } else if process.run_time() > 60 * 60 {
            runtime = (process.run_time() / 60 / 60).to_string() + " Horas";
        } else if process.run_time() > 60 {
            runtime = (process.run_time() / 60).to_string() + " Minutos";
        } else {
            runtime = process.run_time().to_string() + " Segundos";
        }
        let mut proc_info: HashMap<String, String> = HashMap::new();
        proc_info.insert("PID".to_string(), pid.to_string());
        proc_info.insert(
            "Name".to_string(),
            process.name().to_str().unwrap().to_string(),
        );
        proc_info.insert("CPU".to_string(), format!("{:.2}", process.cpu_usage()));
        proc_info.insert(
            "Memory".to_string(),
            (process.memory() / 1024 / 1024).to_string(),
        );
        proc_info.insert(
            "Disk".to_string(),
            ((process.disk_usage().total_read_bytes + process.disk_usage().total_written_bytes)
                / 1024
                / 1024)
                .to_string(),
        );
        proc_info.insert("Path".to_string(), exe.to_string());
        proc_info.insert("Runtime".to_string(), runtime.to_string());
        procs.push(proc_info);
    }
    procs
}
fn to_hashmap(lines: str::Lines, last_header: &str) -> Vec<HashMap<String, String>> {
    let mut data = vec![];
    let mut hash_map = HashMap::new();

    for line in lines {
        let line = line.trim(); // Remove espaços extras e caracteres de controle
        if line.is_empty() {
            continue; // Ignora linhas vazias
        }

        // Divide a linha no delimitador "="
        if let Some((key, value)) = line.split_once('=') {
            hash_map.insert(key.trim().to_string(), value.trim().to_string());
        } else {
            continue; // Ignora linhas inválidas
        }

        // Verifica se o cabeçalho atual é o último e salva o mapa
        if line.starts_with(last_header) {
            data.push(hash_map.clone());
            hash_map.clear();
        }
    }

    // Salva o último hash_map, caso ainda existam dados
    if !hash_map.is_empty() {
        data.push(hash_map);
    }

    data
}
