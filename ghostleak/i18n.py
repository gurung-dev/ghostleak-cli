"""English and Nepali UI labels, finding titles, and hardening tips."""

from __future__ import annotations

STRINGS = {
    "en": {
        "tagline": "local  |  offline  |  secrets redacted  |  zero network",
        "exposure": "exposure",
        "ghost_id": "ghost id",
        "sources": "sources",
        "readout": "scan readout",
        "findings": "findings",
        "tips": "hardening tips",
        "disclaimer": (
            "Educational self-audit of this device only. GhostLeak does not open "
            "network connections, and it never prints secret values."
        ),
        "not_available": "[NOT AVAILABLE]",
        "restricted": "[RESTRICTED]",
        "ok": "ok",
        "warn": "warn",
        "yes": "yes",
        "no": "no",
        "none": "none",
        "unknown": "unknown",
        "active": "active",
        "inactive": "inactive",
        "root": "root",
        "unprivileged": "unprivileged",
        "exposed": "EXPOSED",
        "lan": "LAN",
        "local": "LOCAL",
        "listeners_none": "no listening TCP/UDP sockets found",
        "browsers_none": "no desktop browsers detected",
        "no_findings": "No scored exposure signals. Nothing in the weight table fired.",
        "no_tips": "No hardening tips. The scored checks came back clean.",
        "weights_hint": "Score uses the static weight table (capped at 100).",
        "kali_extra": " On Kali, lab services are common; bind them to 127.0.0.1 outside the lab.",
        "probe": {
            "os": "OS & Device Fingerprint",
            "network": "Network & VPN/Proxy Posture",
            "ports": "Open Listening Ports",
            "env": "Environment & Shell Exposure",
            "firewall": "Firewall & Hardening",
            "browser": "Browser Privacy Footprint",
        },
        "field": {
            "system": "system",
            "distro": "distro",
            "kernel": "kernel",
            "arch": "arch",
            "cpu": "cpu",
            "hostname": "hostname",
            "termux": "termux",
            "android": "android",
            "timezone": "timezone",
            "locale": "locale",
            "python": "python",
            "gateway": "gateway",
            "dns": "dns",
            "vpn": "vpn",
            "proxy": "proxy",
            "firewall": "firewall",
            "privileges": "privileges",
            "sensitive": "sensitive",
            "ssh": "ssh",
            "history": "history",
            "secrets": "secrets",
            "method": "method",
        },
        "tier": {
            "LOW": "LOW",
            "MODERATE": "MODERATE",
            "HIGH": "HIGH",
            "CRITICAL": "CRITICAL",
        },
        "severity": {
            "info": "INFO",
            "low": "LOW",
            "moderate": "MODERATE",
            "high": "HIGH",
            "critical": "CRITICAL",
        },
        "note": {
            "privacy-signal": "privacy signal found",
            "no-privacy-signal": "no privacy extension or user.js",
            "unknown": "profile not inspected",
            "privacy-browser": "privacy-focused browser",
            "not-inspected": "installed; cookies and history were not read",
        },
        "share_title": "GhostLeak CLI  |  safe share",
        "share_note": "100% offline  |  no host identifiers",
    },
    "ne": {
        "tagline": "स्थानीय  |  अफलाइन  |  गोप्य मान लुकाइएको  |  शून्य नेटवर्क",
        "exposure": "एक्सपोजर",
        "ghost_id": "घोस्ट आइडी",
        "sources": "स्रोत",
        "readout": "स्क्यान रिडआउट",
        "findings": "निष्कर्ष",
        "tips": "कडा बनाउने सुझाव",
        "disclaimer": (
            "यो शैक्षिक स्थानीय जाँच हो। GhostLeak ले नेटवर्क कल गर्दैन र गोप्य मान कहिल्यै देखाउँदैन।"
        ),
        "not_available": "[उपलब्ध छैन]",
        "restricted": "[प्रतिबन्धित]",
        "ok": "ठीक",
        "warn": "चेतावनी",
        "yes": "हो",
        "no": "होइन",
        "none": "कुनै छैन",
        "unknown": "अज्ञात",
        "active": "सक्रिय",
        "inactive": "निष्क्रिय",
        "root": "रुट",
        "unprivileged": "सामान्य प्रयोगकर्ता",
        "exposed": "खुला",
        "lan": "ल्यान",
        "local": "स्थानीय",
        "listeners_none": "कुनै सुन्ने TCP/UDP सकेट भेटिएन",
        "browsers_none": "कुनै डेस्कटप ब्राउजर भेटिएन",
        "no_findings": "अंकित एक्सपोजर संकेत छैन। वजन तालिकाको कुनै बुँदा सक्रिय भएन।",
        "no_tips": "कुनै सुझाव छैन। जाँचिएका बुँदाहरू सफा छन्।",
        "weights_hint": "स्कोर स्थिर वजन तालिकाबाट आउँछ (अधिकतम १००)। जोखिम स्तर यही स्कोर हो।",
        "kali_extra": " कालीमा प्रयोगशाला सेवा सामान्य हुन्छ; प्रयोगशालाबाहिर 127.0.0.1 मा बाँध्नुहोस्।",
        "probe": {
            "os": "अपरेटिङ सिस्टम र उपकरण",
            "network": "नेटवर्क तथा भिपिएन/प्रोक्सी",
            "ports": "खुला सुन्ने पोर्टहरू",
            "env": "वातावरण चर र शेल जोखिम",
            "firewall": "फायरवाल र कडा सुरक्षा",
            "browser": "ब्राउजर गोपनीयता",
        },
        "field": {
            "system": "सिस्टम",
            "distro": "डिस्ट्रो",
            "kernel": "कर्नेल",
            "arch": "आर्किटेक्चर",
            "cpu": "प्रोसेसर",
            "hostname": "होस्टनाम",
            "termux": "टर्मक्स",
            "android": "एन्ड्रोइड",
            "timezone": "समय क्षेत्र",
            "locale": "लोकेल",
            "python": "पाइथन",
            "gateway": "गेटवे",
            "dns": "डिएनएस",
            "vpn": "भिपिएन",
            "proxy": "प्रोक्सी",
            "firewall": "फायरवाल",
            "privileges": "विशेषाधिकार",
            "sensitive": "संवेदनशील",
            "ssh": "एसएसएच",
            "history": "इतिहास",
            "secrets": "गोप्य फाइल",
            "method": "विधि",
        },
        "tier": {
            "LOW": "न्यून",
            "MODERATE": "मध्यम",
            "HIGH": "उच्च",
            "CRITICAL": "गम्भीर",
        },
        "severity": {
            "info": "जानकारी",
            "low": "न्यून",
            "moderate": "मध्यम",
            "high": "उच्च",
            "critical": "गम्भीर",
        },
        "note": {
            "privacy-signal": "गोपनीयता संकेत भेटियो",
            "no-privacy-signal": "गोपनीयता एक्सटेन्सन वा user.js छैन",
            "unknown": "प्रोफाइल जाँचिएन",
            "privacy-browser": "गोपनीयता केन्द्रित ब्राउजर",
            "not-inspected": "स्थापित; कुकी र इतिहास पढिएन",
        },
        "share_title": "GhostLeak CLI  |  सुरक्षित साझेदारी",
        "share_note": "१००% अफलाइन  |  होस्ट पहिचान छैन",
    },
}

FINDINGS = {
    "en": {
        "wildcard_listener": {
            "title": "{count} socket(s) listening on all interfaces ({examples})",
            "tips": {
                "termux": "In Termux, bind services to localhost. Set `ListenAddress 127.0.0.1` in `$PREFIX/etc/ssh/sshd_config`, then restart sshd.",
                "darwin": "Bind the service to 127.0.0.1 instead of 0.0.0.0 or ::. Turn off unused listeners in System Settings > Sharing.",
                "linux": "Bind the service to 127.0.0.1. For OpenSSH, set `ListenAddress 127.0.0.1` in `/etc/ssh/sshd_config` and restart sshd.",
                "other": "Bind listeners to 127.0.0.1 or ::1 unless they must be reached from other hosts.",
            },
        },
        "interface_listener": {
            "title": "{count} socket(s) bound to a specific non-loopback address ({examples})",
            "tips": {
                "termux": "These sockets are reachable beyond this device ({examples}). Bind them to 127.0.0.1 if remote clients are not required.",
                "darwin": "These sockets are bound to a routable address ({examples}). Use 127.0.0.1 when other hosts do not need them.",
                "linux": "These sockets are bound to a routable address ({examples}). Bind to 127.0.0.1 if remote access is not required.",
                "other": "These sockets are bound beyond loopback ({examples}). Prefer 127.0.0.1 unless remote access is required.",
            },
        },
        "no_vpn": {
            "title": "Routable network is up and no VPN/tunnel interface was detected",
            "tips": {
                "termux": "No tun*, wg*, utun*, or tailscale* interface was seen. On untrusted networks, connect a VPN app or WireGuard.",
                "darwin": "No utun*, wg*, or tailscale* interface was seen. Turn on WireGuard, Tailscale, or your VPN provider.",
                "linux": "No tun*, wg*, or tailscale* interface was seen. Bring up WireGuard (`wg-quick up <name>`) or Tailscale if you want a tunnel.",
                "other": "No VPN/tunnel interface was detected. Use a tunnel on networks you do not trust.",
            },
        },
        "sensitive_env": {
            "title": "{count} sensitive environment name(s): {names} = [REDACTED]",
            "tips": {
                "termux": "These names are visible to processes you start: {names}. Remove unused exports from the shell startup file. Values are not printed.",
                "darwin": "These names are visible to every child process: {names}. Drop unused exports from ~/.zshrc and pass secrets only to the command that needs them.",
                "linux": "These names are visible to every child process: {names}. Remove unused exports from ~/.bashrc or ~/.zshrc. GhostLeak does not print the values.",
                "other": "Sensitive names are set in this process: {names}. Unset the ones you do not need. Values stay [REDACTED].",
            },
        },
        "ssh_world_readable": {
            "title": "SSH path is world-accessible ({paths})",
            "tips": {
                "termux": "Other apps or users may read SSH material ({paths}). Run: chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_* ~/.ssh/*.pem ~/.ssh/config ~/.ssh/authorized_keys",
                "darwin": "SSH material is world-accessible ({paths}). Run: chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_* ~/.ssh/*.pem ~/.ssh/config ~/.ssh/authorized_keys",
                "linux": "SSH material is world-accessible ({paths}). Run: chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_* ~/.ssh/*.pem ~/.ssh/config ~/.ssh/authorized_keys",
                "other": "SSH material is world-accessible ({paths}). Restrict the directory to 700 and private keys to 600.",
            },
        },
        "ssh_permissive": {
            "title": "SSH path is group-readable ({paths})",
            "tips": {
                "termux": "Group can read SSH material ({paths}). Run: chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_* ~/.ssh/config ~/.ssh/authorized_keys",
                "darwin": "Group can read SSH material ({paths}). Run: chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_* ~/.ssh/config ~/.ssh/authorized_keys",
                "linux": "Group can read SSH material ({paths}). Run: chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_* ~/.ssh/config ~/.ssh/authorized_keys",
                "other": "Group can read SSH material ({paths}). Use mode 700 for ~/.ssh and 600 for private keys.",
            },
        },
        "history_world_readable": {
            "title": "Shell history is world-readable ({paths})",
            "tips": {
                "termux": "History files can contain tokens you typed ({paths}). Run: chmod 600 ~/.bash_history ~/.zsh_history ~/.sh_history",
                "darwin": "History files can contain tokens you typed ({paths}). Run: chmod 600 ~/.zsh_history ~/.bash_history",
                "linux": "History files can contain tokens you typed ({paths}). Run: chmod 600 ~/.bash_history ~/.zsh_history ~/.sh_history",
                "other": "History files are world-readable ({paths}). Restrict them to mode 600. Contents were not read.",
            },
        },
        "history_group_readable": {
            "title": "Shell history is group-readable ({paths})",
            "tips": {
                "termux": "Group can read shell history ({paths}). Run: chmod 600 ~/.bash_history ~/.zsh_history ~/.sh_history",
                "darwin": "Group can read shell history ({paths}). Run: chmod 600 ~/.zsh_history ~/.bash_history",
                "linux": "Group can read shell history ({paths}). Run: chmod 600 ~/.bash_history ~/.zsh_history ~/.sh_history",
                "other": "Group can read shell history ({paths}). Restrict those files to mode 600.",
            },
        },
        "secret_file_exposed": {
            "title": "Credential file is world-readable ({paths})",
            "tips": {
                "termux": "A credential file is world-readable ({paths}). Run chmod 600 on it. The contents were not read.",
                "darwin": "A credential file is world-readable ({paths}). Run chmod 600 on it and keep it out of git. Contents were not read.",
                "linux": "A credential file is world-readable ({paths}). Run chmod 600 on it and keep it out of git. Contents were not read.",
                "other": "A credential file is world-readable ({paths}). Restrict it to mode 600. Contents were not read.",
            },
        },
        "secret_file_group": {
            "title": "Credential file is group-readable ({paths})",
            "tips": {
                "termux": "A credential file is group-readable ({paths}). Run chmod 600 on it. Contents were not read.",
                "darwin": "A credential file is group-readable ({paths}). Run chmod 600 on it. Contents were not read.",
                "linux": "A credential file is group-readable ({paths}). Run chmod 600 on it. Contents were not read.",
                "other": "A credential file is group-readable ({paths}). Restrict it to mode 600.",
            },
        },
        "config_world_writable": {
            "title": "Shell startup file is world-writable ({paths})",
            "tips": {
                "termux": "Another local user could change your shell startup ({paths}). Run: chmod u+rw,go-w on that file.",
                "darwin": "Another local user could change your shell startup ({paths}). Run: chmod u+rw,go-w on that file.",
                "linux": "Another local user could change your shell startup ({paths}). Run: chmod u+rw,go-w on that file. Mode 644 is typical for rc files.",
                "other": "A shell startup file is world-writable ({paths}). Remove other-write permission.",
            },
        },
        "firewall_off": {
            "title": "Host firewall reports inactive ({tool})",
            "tips": {
                "termux": "Termux cannot control the Android host firewall. Avoid listening on 0.0.0.0 and use a VPN on untrusted networks.",
                "darwin": "Turn the application firewall on: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
                "linux": "Enable a host firewall, for example: sudo ufw enable",
                "other": "Enable the host firewall and default to denying unsolicited inbound connections.",
            },
        },
        "firewall_unknown": {
            "title": "Host firewall state could not be read",
            "tips": {
                "termux": "Termux has no host firewall namespace. [NOT AVAILABLE] here is expected, not a crash.",
                "darwin": "Firewall state was not readable. Check System Settings > Network > Firewall. Do not re-run the whole scan as root just to see this.",
                "linux": "Firewall state was not readable without privileges. Check `sudo ufw status` or `sudo nft list ruleset`. Unknown scores 4; running the scan as root scores 12.",
                "other": "This platform did not expose a supported firewall probe.",
            },
        },
        "running_as_root": {
            "title": "This scan is running as root",
            "tips": {
                "termux": "Root is uncommon in Termux and is scored as exposure. Use a normal session for day-to-day work.",
                "darwin": "Run GhostLeak as your user. Root is scored on its own. Use sudo only for the firewall command above.",
                "linux": "Run GhostLeak as a normal user. Root is scored on its own. Use sudo only for the firewall command above.",
                "other": "Run GhostLeak as an unprivileged user. Use elevated rights only for a specific firewall command.",
            },
        },
        "browser_no_privacy": {
            "title": "Browser without a detected privacy profile: {names}",
            "tips": {
                "termux": "No privacy signal was found for {names}. Install a content blocker if you use a graphical browser. Cookies, passwords, and history were not read.",
                "darwin": "No Firefox user.js and no known content-blocker folder was found for {names}. Install uBlock Origin, or use LibreWolf / Tor Browser. Cookies and passwords were not read.",
                "linux": "No Firefox user.js and no known content-blocker folder was found for {names}. Install uBlock Origin, or use LibreWolf / Tor Browser. Cookies and passwords were not read.",
                "other": "No privacy signal was found for {names}. A content blocker or a privacy-focused browser lowers this finding. Stores were not read.",
            },
        },
    },
    "ne": {
        "wildcard_listener": {
            "title": "{count} सकेट सबै इन्टरफेसमा सुन्दैछ ({examples})",
            "tips": {
                "termux": "टर्मक्समा सेवालाई लोकलहोस्टमा बाँध्नुहोस्। `$PREFIX/etc/ssh/sshd_config` मा `ListenAddress 127.0.0.1` राखेर sshd पुनः सुरु गर्नुहोस्।",
                "darwin": "सेवालाई 0.0.0.0 वा :: को सट्टा 127.0.0.1 मा बाँध्नुहोस्। System Settings > Sharing मा नचाहिने लिसनर बन्द गर्नुहोस्।",
                "linux": "सेवालाई 127.0.0.1 मा बाँध्नुहोस्। OpenSSH का लागि `/etc/ssh/sshd_config` मा `ListenAddress 127.0.0.1` राखेर sshd पुनः सुरु गर्नुहोस्।",
                "other": "अन्य होस्टबाट चाहिँदैन भने लिसनर 127.0.0.1 वा ::1 मा बाँध्नुहोस्।",
            },
        },
        "interface_listener": {
            "title": "{count} सकेट लूपब्याक बाहेकको ठेगानामा बाँधिएको छ ({examples})",
            "tips": {
                "termux": "यी सकेट यो उपकरणबाहिर पुग्न सक्छन् ({examples})। टाढाको क्लाइन्ट नचाहिँदा 127.0.0.1 मा बाँध्नुहोस्।",
                "darwin": "यी सकेट राउट हुने ठेगानामा छन् ({examples})। अन्य होस्टलाई नचाहिँदा 127.0.0.1 प्रयोग गर्नुहोस्।",
                "linux": "यी सकेट राउट हुने ठेगानामा छन् ({examples})। टाढाको पहुँच नचाहिँदा 127.0.0.1 मा बाँध्नुहोस्।",
                "other": "यी सकेट लूपब्याकबाहिर छन् ({examples})। टाढाको पहुँच नचाहिँदा 127.0.0.1 रोज्नुहोस्।",
            },
        },
        "no_vpn": {
            "title": "राउट हुने नेटवर्क सक्रिय छ र भिपिएन/टनेल इन्टरफेस भेटिएन",
            "tips": {
                "termux": "tun*, wg*, utun*, वा tailscale* इन्टरफेस देखिएन। अविश्वसनीय नेटवर्कमा VPN एप वा WireGuard खोल्नुहोस्।",
                "darwin": "utun*, wg*, वा tailscale* इन्टरफेस देखिएन। WireGuard, Tailscale, वा आफ्नो VPN खोल्नुहोस्।",
                "linux": "tun*, wg*, वा tailscale* इन्टरफेस देखिएन। टनेल चाहिँदा WireGuard (`wg-quick up <name>`) वा Tailscale उठाउनुहोस्।",
                "other": "भिपिएन/टनेल इन्टरफेस भेटिएन। नचिनेको नेटवर्कमा टनेल प्रयोग गर्नुहोस्।",
            },
        },
        "sensitive_env": {
            "title": "{count} संवेदनशील वातावरण नाम: {names} = [REDACTED]",
            "tips": {
                "termux": "यी नामहरू तपाईंले खोल्ने प्रक्रियाले देख्छन्: {names}। नचाहिने export हटाउनुहोस्। मान देखाइँदैन।",
                "darwin": "यी नामहरू हरेक चाइल्ड प्रक्रियाले देख्छन्: {names}। ~/.zshrc बाट नचाहिने export हटाउनुहोस्।",
                "linux": "यी नामहरू हरेक चाइल्ड प्रक्रियाले देख्छन्: {names}। ~/.bashrc वा ~/.zshrc बाट नचाहिने export हटाउनुहोस्। मान देखाइँदैन।",
                "other": "यस प्रक्रियामा संवेदनशील नाम छन्: {names}। नचाहिनेहरू unset गर्नुहोस्। मान [REDACTED] नै रहन्छ।",
            },
        },
        "ssh_world_readable": {
            "title": "एसएसएच पथ संसारले पढ्न सक्छ ({paths})",
            "tips": {
                "termux": "अन्य एपले एसएसएच सामग्री पढ्न सक्छ ({paths})। चलाउनुहोस्: chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_* ~/.ssh/*.pem ~/.ssh/config ~/.ssh/authorized_keys",
                "darwin": "एसएसएच सामग्री संसारले पढ्न सक्छ ({paths})। चलाउनुहोस्: chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_* ~/.ssh/*.pem ~/.ssh/config ~/.ssh/authorized_keys",
                "linux": "एसएसएच सामग्री संसारले पढ्न सक्छ ({paths})। चलाउनुहोस्: chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_* ~/.ssh/*.pem ~/.ssh/config ~/.ssh/authorized_keys",
                "other": "एसएसएच सामग्री संसारले पढ्न सक्छ ({paths})। डाइरेक्टरी 700 र निजी साँचो 600 बनाउनुहोस्।",
            },
        },
        "ssh_permissive": {
            "title": "एसएसएच पथ समूहले पढ्न सक्छ ({paths})",
            "tips": {
                "termux": "समूहले एसएसएच सामग्री पढ्न सक्छ ({paths})। चलाउनुहोस्: chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_* ~/.ssh/config ~/.ssh/authorized_keys",
                "darwin": "समूहले एसएसएच सामग्री पढ्न सक्छ ({paths})। चलाउनुहोस्: chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_* ~/.ssh/config ~/.ssh/authorized_keys",
                "linux": "समूहले एसएसएच सामग्री पढ्न सक्छ ({paths})। चलाउनुहोस्: chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_* ~/.ssh/config ~/.ssh/authorized_keys",
                "other": "समूहले एसएसएच सामग्री पढ्न सक्छ ({paths})। ~/.ssh लाई 700 र निजी साँचोलाई 600 बनाउनुहोस्।",
            },
        },
        "history_world_readable": {
            "title": "शेल इतिहास संसारले पढ्न सक्छ ({paths})",
            "tips": {
                "termux": "इतिहास फाइलमा टाइप गरेका टोकन हुन सक्छन् ({paths})। चलाउनुहोस्: chmod 600 ~/.bash_history ~/.zsh_history ~/.sh_history",
                "darwin": "इतिहास फाइलमा टाइप गरेका टोकन हुन सक्छन् ({paths})। चलाउनुहोस्: chmod 600 ~/.zsh_history ~/.bash_history",
                "linux": "इतिहास फाइलमा टाइप गरेका टोकन हुन सक्छन् ({paths})। चलाउनुहोस्: chmod 600 ~/.bash_history ~/.zsh_history ~/.sh_history",
                "other": "इतिहास फाइल संसारले पढ्न सक्छ ({paths})। मोड 600 बनाउनुहोस्। सामग्री पढिएन।",
            },
        },
        "history_group_readable": {
            "title": "शेल इतिहास समूहले पढ्न सक्छ ({paths})",
            "tips": {
                "termux": "समूहले शेल इतिहास पढ्न सक्छ ({paths})। चलाउनुहोस्: chmod 600 ~/.bash_history ~/.zsh_history ~/.sh_history",
                "darwin": "समूहले शेल इतिहास पढ्न सक्छ ({paths})। चलाउनुहोस्: chmod 600 ~/.zsh_history ~/.bash_history",
                "linux": "समूहले शेल इतिहास पढ्न सक्छ ({paths})। चलाउनुहोस्: chmod 600 ~/.bash_history ~/.zsh_history ~/.sh_history",
                "other": "समूहले शेल इतिहास पढ्न सक्छ ({paths})। ती फाइल 600 बनाउनुहोस्।",
            },
        },
        "secret_file_exposed": {
            "title": "गोप्य फाइल संसारले पढ्न सक्छ ({paths})",
            "tips": {
                "termux": "गोप्य फाइल संसारले पढ्न सक्छ ({paths})। chmod 600 चलाउनुहोस्। सामग्री पढिएन।",
                "darwin": "गोप्य फाइल संसारले पढ्न सक्छ ({paths})। chmod 600 चलाउनुहोस् र git मा नराख्नुहोस्। सामग्री पढिएन।",
                "linux": "गोप्य फाइल संसारले पढ्न सक्छ ({paths})। chmod 600 चलाउनुहोस् र git मा नराख्नुहोस्। सामग्री पढिएन।",
                "other": "गोप्य फाइल संसारले पढ्न सक्छ ({paths})। मोड 600 बनाउनुहोस्। सामग्री पढिएन।",
            },
        },
        "secret_file_group": {
            "title": "गोप्य फाइल समूहले पढ्न सक्छ ({paths})",
            "tips": {
                "termux": "गोप्य फाइल समूहले पढ्न सक्छ ({paths})। chmod 600 चलाउनुहोस्। सामग्री पढिएन।",
                "darwin": "गोप्य फाइल समूहले पढ्न सक्छ ({paths})। chmod 600 चलाउनुहोस्। सामग्री पढिएन।",
                "linux": "गोप्य फाइल समूहले पढ्न सक्छ ({paths})। chmod 600 चलाउनुहोस्। सामग्री पढिएन।",
                "other": "गोप्य फाइल समूहले पढ्न सक्छ ({paths})। मोड 600 बनाउनुहोस्।",
            },
        },
        "config_world_writable": {
            "title": "शेल सुरुवात फाइल संसारले लेख्न सक्छ ({paths})",
            "tips": {
                "termux": "अर्को स्थानीय प्रयोगकर्ताले शेल सुरुवात बदल्न सक्छ ({paths})। chmod u+rw,go-w चलाउनुहोस्।",
                "darwin": "अर्को स्थानीय प्रयोगकर्ताले शेल सुरुवात बदल्न सक्छ ({paths})। chmod u+rw,go-w चलाउनुहोस्।",
                "linux": "अर्को स्थानीय प्रयोगकर्ताले शेल सुरुवात बदल्न सक्छ ({paths})। chmod u+rw,go-w चलाउनुहोस्। rc फाइलका लागि 644 सामान्य हो।",
                "other": "शेल सुरुवात फाइल संसारले लेख्न सक्छ ({paths})। other-write अनुमति हटाउनुहोस्।",
            },
        },
        "firewall_off": {
            "title": "होस्ट फायरवाल निष्क्रिय रिपोर्ट भयो ({tool})",
            "tips": {
                "termux": "टर्मक्सले एन्ड्रोइड होस्ट फायरवाल नियन्त्रण गर्दैन। 0.0.0.0 मा नसुन्नुहोस् र अविश्वसनीय नेटवर्कमा VPN प्रयोग गर्नुहोस्।",
                "darwin": "एप्लिकेसन फायरवाल खोल्नुहोस्: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
                "linux": "होस्ट फायरवाल सक्रिय गर्नुहोस्, उदाहरण: sudo ufw enable",
                "other": "होस्ट फायरवाल खोल्नुहोस् र नचाहिएको इनबाउन्ड जडान अस्वीकार गर्नुहोस्।",
            },
        },
        "firewall_unknown": {
            "title": "होस्ट फायरवालको अवस्था पढ्न सकिएन",
            "tips": {
                "termux": "टर्मक्समा होस्ट फायरवाल नेमस्पेस हुँदैन। यहाँ [उपलब्ध छैन] अपेक्षित हो, क्र्यास होइन।",
                "darwin": "फायरवाल अवस्था पढ्न सकिएन। System Settings > Network > Firewall हेर्नुहोस्। यसका लागि पूरै स्क्यान रुटबाट नचलाउनुहोस्।",
                "linux": "अधिकार बिना फायरवाल अवस्था पढ्न सकिएन। `sudo ufw status` वा `sudo nft list ruleset` हेर्नुहोस्। अज्ञातले ४ अंक दिन्छ; रुटबाट स्क्यानले १२।",
                "other": "यो प्लेटफर्ममा समर्थित फायरवाल प्रोब भेटिएन।",
            },
        },
        "running_as_root": {
            "title": "यो स्क्यान रुटको रूपमा चलिरहेको छ",
            "tips": {
                "termux": "टर्मक्समा रुट असामान्य हो र यसलाई एक्सपोजर मानिन्छ। दैनिक काम सामान्य सत्रमा गर्नुहोस्।",
                "darwin": "GhostLeak आफ्नो प्रयोगकर्ताबाट चलाउनुहोस्। रुट छुट्टै अंकित हुन्छ। sudo केवल माथिको फायरवाल आदेशका लागि प्रयोग गर्नुहोस्।",
                "linux": "GhostLeak सामान्य प्रयोगकर्ताबाट चलाउनुहोस्। रुट छुट्टै अंकित हुन्छ। sudo केवल माथिको फायरवाल आदेशका लागि प्रयोग गर्नुहोस्।",
                "other": "GhostLeak विशेषाधिकारविहीन प्रयोगकर्ताबाट चलाउनुहोस्। उन्नत अधिकार केवल निश्चित फायरवाल आदेशका लागि।",
            },
        },
        "browser_no_privacy": {
            "title": "गोपनीयता प्रोफाइल नभेटिएको ब्राउजर: {names}",
            "tips": {
                "termux": "{names} मा गोपनीयता संकेत भेटिएन। ग्राफिकल ब्राउजर प्रयोग गर्दा सामग्री रोक्ने एक्सटेन्सन राख्नुहोस्। कुकी, पासवर्ड, र इतिहास पढिएन।",
                "darwin": "{names} मा Firefox user.js वा चिनिएको कन्टेन्ट-ब्लकर फोल्डर भेटिएन। uBlock Origin राख्नुहोस्, वा LibreWolf / Tor Browser प्रयोग गर्नुहोस्। कुकी र पासवर्ड पढिएन।",
                "linux": "{names} मा Firefox user.js वा चिनिएको कन्टेन्ट-ब्लकर फोल्डर भेटिएन। uBlock Origin राख्नुहोस्, वा LibreWolf / Tor Browser प्रयोग गर्नुहोस्। कुकी र पासवर्ड पढिएन।",
                "other": "{names} मा गोपनीयता संकेत भेटिएन। कन्टेन्ट ब्लकर वा गोपनीयता ब्राउजरले यो निष्कर्ष घटाउँछ। भण्डार पढिएन।",
            },
        },
    },
}


class _Safe(dict):
    def __missing__(self, key):
        return ""


def normalize_lang(lang: str) -> str:
    if not lang:
        return "en"
    value = str(lang).strip().lower()
    if value in STRINGS:
        return value
    return "en"


def t(lang: str, key: str, **kwargs) -> str:
    """Look up a dotted UI string, falling back to English."""

    def lookup(table):
        node = table
        for part in key.split("."):
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node

    text = lookup(STRINGS.get(normalize_lang(lang), {}))
    if not isinstance(text, str):
        text = lookup(STRINGS["en"])
    if not isinstance(text, str):
        return key
    if kwargs:
        try:
            return text.format_map(_Safe(kwargs))
        except Exception:
            return text
    return text


def tier_label(lang: str, tier: str) -> str:
    return t(lang, f"tier.{tier}")


def severity_label(lang: str, severity: str) -> str:
    return t(lang, f"severity.{severity}")


def share_line(lang: str, score: int, tier: str) -> str:
    label = tier_label(lang, tier)
    if normalize_lang(lang) == "ne":
        return f"GhostLeak CLI स्कोर: {score}/100 [{label}]"
    return f"GhostLeak CLI Score: {score}/100 [{label}]"


def _finding_block(lang: str, code: str) -> dict:
    table = FINDINGS.get(normalize_lang(lang), {})
    block = table.get(code)
    if not block:
        block = FINDINGS["en"].get(code)
    if not block:
        return {"title": code, "tips": {}}
    return block


def describe(finding, lang: str, family: str, distro_id: str = ""):
    """Return (title, tip) for a finding. Placeholders come from finding.params."""
    block = _finding_block(lang, finding.code)
    params = _Safe()
    try:
        params.update(finding.params or {})
    except Exception:
        pass
    try:
        title = str(block.get("title") or finding.code).format_map(params)
    except Exception:
        title = str(block.get("title") or finding.code)
    tips = block.get("tips") or {}
    tip = tips.get(family) or tips.get("other") or tips.get("linux") or ""
    try:
        tip = str(tip).format_map(params)
    except Exception:
        tip = str(tip)
    if finding.code == "wildcard_listener" and str(distro_id or "").lower() == "kali":
        tip = tip.rstrip() + t(lang, "kali_extra")
    return title, tip
