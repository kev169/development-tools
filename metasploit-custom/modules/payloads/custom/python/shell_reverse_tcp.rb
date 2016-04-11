##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

    include Msf::Payload::Single
    include Msf::Sessions::CommandShellOptions

    def initialize(info = {})
        super(merge_info(info, 
            'Name'      => 'Dummy python template',
            'Description' => 'Creates an interactive shell via python', 
            'Author'    => 'Kevin Haubris',
            'License'   => MSF_LICENSE,
            'Platform'  => 'python',
            'Arch'      => ARCH_PYTHON,
            'Handler'   => Msf::Handler::ReverseTcp,
            'Session'   => Msf::Sessions::CommandShell,
            'PayloadType' => 'python',
            'Payload'   =>
                {
                    'Offsets' => {},
                    'Payload' => ''
                }
            ))
    end

    def generate
        super + command_string
    end

    def command_string
        cmd = ''
        #create random string 
        #dead = Rex::Text.rand_text_alpha(2)
        #base 64 encoding
        # Rex::Text.encode_base64(cmd)
        cmd << "this is a dummy payload"

        cmd
    end
end
