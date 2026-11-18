### Added
- **The device doctor says when another program answers the tunnel's DNS.** Some VPN
  clients enforce their own DNS with a driver that answers every UDP/53 question on
  the machine, whatever address it goes to. Next to such a client the tunnel connects
  and applications given by address open, but names of tunneled applications never
  resolve, and nothing said why. The doctor has a new check, "Tunnel name lookup",
  run while the tunnel is connected: it asks one question of an address nobody on the
  device owns, where nothing legitimate answers, and a reply means a driver is
  answering. It shows a warning (`DNS_INTERCEPTED`) with what to ask IT, the console
  explains it in English and Turkish, and the server counts it as a cause (ranked
  after the network causes) when a named application does not open. The support code
  carries it; codes read out before this change still decode.
