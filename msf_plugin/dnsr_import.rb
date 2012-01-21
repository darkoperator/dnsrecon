module Msf

    class Plugin::PostCommand < Msf::Plugin

        class MultiCommand
            include Msf::Ui::Console::CommandDispatcher

            # Set name for command dispatcher
            def name
                "DNSR_Import"
            end

            # Define Commands
            def commands
                {
                    "import_dnsrecon_xml" => "Import DNSRecon XML output file."
                }
            end

            def report_host(ip)
                print_good("Importing host #{ip}")
                framework.db.report_host({:host => ip})
            end

            def report_service(name, proto, port, target)
                print_good("Importing service #{name} for host #{target}")
                framework.db.report_service({
                        :host  => target,
                        :name  => name,
                        :port  => port,
                        :proto => proto
                    })
            end

            def parse_records(xm_file)
                require "nokogiri"
                reader = Nokogiri::XML::Reader(IO.read(xm_file))
				reader.each do |node|
					if node.name == 'record'
						case node.attribute('type')

						when /PTR|^[A]$|AAAA/
							report_host(node.attribute('address'))

							# Since several hosts can be tied to one IP, specially those that are vhosts
							# or are behind a balancer the names are saved as notes.
							framework.db.report_note({
									:host  => node.attribute('address'),
									:ntype => "dns.info",
									:data  => "A #{node.attribute('name')}",
									:update => :unique_data
								})

						 when /NS/
							report_host(node.attribute('address'))
							report_service("dns", "udp", 53, node.attribute('address'))
							framework.db.report_note({
									:host  => node.attribute('address'),
									:port  => 53,
									:proto => "udp",
									:ntype => "dns.info",
									:data  => "NS #{node.attribute('target')}"
								})

						when /SOA/
							report_host(node.attribute('address'))
							report_service("dns", "udp", 53, node.attribute('address'))
							framework.db.report_note({
									:host  => node.attribute('address'),
									:port  => 53,
									:proto => "udp",
									:type  => "dns.info",
									:data  => "NS #{node.attribute('mname')}"
								})

						when /MX/
							report_host(node.attribute('address'))
							report_service("smtp", "tcp", 25, node.attribute('address'))
							framework.db.report_note({
									:host  => node.attribute('address'),
									:port  => 25,
									:proto => "tcp",
									:type  => "dns.info",
									:data  => "MX #{node.attribute('exchange')}"
								})

						when /SRV/
							srv_info = []
							srv_info = node.attribute('name').strip.scan(/^_(\S*)\._(tcp|udp|tls)\./)[0]
							port = node.attribute('port').strip.to_i
							if srv_info[1] == "tls"
								proto = "tcp"
							else
								proto = srv_info[1]
							end
							report_host(node.attribute('address'))
							report_service(srv_info[0], proto, port, node.attribute('address'))
							framework.db.report_note({
									:host  => node.attribute('address'),
									:port  => port,
									:proto => proto,
									:type  => "dns.info",
									:data  => "SRV #{node.attribute('target')}"
								})
						end
					end
                end
            end
            # Multi shell command
            def cmd_import_dnsrecon_xml(*args)
                # Define options
                opts = Rex::Parser::Arguments.new(
                    "-f"   => [ true,	"XML file to import."],
                    "-h"   => [ false,  "Command Help"]
                )

                # set variables for options
                xml_file = ""

                # Parse options
                opts.parse(args) do |opt, idx, val|
                    case opt
					when "-f"
						xml_file = val

					when "-h"
						print_line(opts.usage)
						return
                    end
                end

                if not ::File.exists?(xml_file)
						print_error "XML File does not exists!"
						return
				else
                        parse_records(xml_file)
                end

            end

			def cmd_import_dnsrecon_xml_tabs(str, words)
				tab_complete_filenames(str, words)
			end
        end

        def initialize(framework, opts)
            super
            add_console_dispatcher(MultiCommand)
            print_status("dnsr_import plugin loaded.")
        end

        def cleanup
            remove_console_dispatcher("DNSR_Import")
        end

        def name
            "dnsr_import"
        end

        def desc
            "Allows to import DNSRecon output XML files."
        end

        protected
    end

end