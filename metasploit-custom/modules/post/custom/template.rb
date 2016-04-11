require 'msf/core'

class Metasploit3 < Msf::Post

    include Msf::Post::Linux::System

    def initialize(info={})
        super( update_info( info, 
            'Name'      => 'Linux template',
            'Description'   => %q{
                This is a template module for linux post modules.
            },
            'License'   => MSF_LICENSE,
            'Author'    => [
                'Kevin Haubris <kevin.haubris@gmail.com>',
            ],
            'Platform'  => ['linux'],
            'SessionTypes'  => ['shell', 'meterpreter']
        ))
    end

    def run
        distro = get_sysinfo
        h = get_host
        print_status("Running against #{h}")
        print_status("Distro version: #{distro[:version]}")
    end

    def get_host
    case session.type
    when /meterpreter/
        host = sysinfo["Computer"]
    when /shell/
        host = cmd_exec("hostname").chomp
    end
    return host
    end
end
