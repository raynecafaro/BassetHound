use libc;
use std::collections::HashMap;

/// Query the Linux Kernel Module via custom Netlink socket
pub fn query_lkm() -> Result<HashMap<i32, String>, String> {
    unsafe {
        let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, 31);
        if fd < 0 {
            return Err(format!(
                "Failed to open netlink socket: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Bind socket
        let mut src_addr: libc::sockaddr_nl = std::mem::zeroed();
        src_addr.nl_family = libc::AF_NETLINK as u16;
        src_addr.nl_pid = std::process::id(); // self PID
        src_addr.nl_groups = 0; // unicast

        let res = libc::bind(
            fd,
            &src_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        );
        if res < 0 {
            libc::close(fd);
            return Err(format!(
                "Failed to bind netlink socket: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Send request
        let mut dest_addr: libc::sockaddr_nl = std::mem::zeroed();
        dest_addr.nl_family = libc::AF_NETLINK as u16;
        dest_addr.nl_pid = 0; // Destination is kernel
        dest_addr.nl_groups = 0; // unicast

        let mut nlh: libc::nlmsghdr = std::mem::zeroed();
        nlh.nlmsg_len = std::mem::size_of::<libc::nlmsghdr>() as u32;
        nlh.nlmsg_pid = std::process::id();
        nlh.nlmsg_flags = 0;
        nlh.nlmsg_type = 0; // Data request

        let res = libc::sendto(
            fd,
            &nlh as *const _ as *const libc::c_void,
            nlh.nlmsg_len as usize,
            0,
            &dest_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        );

        if res < 0 {
            libc::close(fd);
            return Err(format!(
                "Failed to send netlink request: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Receive loop
        let mut buffer = vec![0u8; 32768];
        let mut processes = HashMap::new();

        loop {
            let res = libc::recv(
                fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
            );
            if res < 0 {
                libc::close(fd);
                return Err(format!(
                    "Failed to receive netlink response: {}",
                    std::io::Error::last_os_error()
                ));
            }

            let received_len = res as usize;
            if received_len < std::mem::size_of::<libc::nlmsghdr>() {
                break;
            }

            let nlh_ptr = buffer.as_ptr() as *const libc::nlmsghdr;
            let nlh = &*nlh_ptr;

            if nlh.nlmsg_type == libc::NLMSG_DONE as u16 {
                let payload_len = nlh.nlmsg_len as usize - std::mem::size_of::<libc::nlmsghdr>();
                if payload_len > 0 {
                    let payload_ptr = buffer.as_ptr().add(std::mem::size_of::<libc::nlmsghdr>());
                    let slice = std::slice::from_raw_parts(payload_ptr, payload_len);
                    if let Ok(text) = String::from_utf8(slice.to_vec()) {
                        parse_proc_list(&text, &mut processes);
                    }
                }
                break;
            }

            let payload_len = nlh.nlmsg_len as usize - std::mem::size_of::<libc::nlmsghdr>();
            let payload_ptr = buffer.as_ptr().add(std::mem::size_of::<libc::nlmsghdr>());
            let slice = std::slice::from_raw_parts(payload_ptr, payload_len);

            if let Ok(text) = String::from_utf8(slice.to_vec()) {
                parse_proc_list(&text, &mut processes);
            }
        }

        libc::close(fd);
        Ok(processes)
    }
}

fn parse_proc_list(text: &str, processes: &mut HashMap<i32, String>) {
    for line in text.lines() {
        let parts: Vec<&str> = line.splitn(2, '\t').collect();
        if parts.len() == 2 {
            if let Ok(pid) = parts[0].parse::<i32>() {
                processes.insert(pid, parts[1].to_string());
            }
        }
    }
}
