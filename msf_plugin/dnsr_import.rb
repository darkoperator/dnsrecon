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
                        :host=> target,
                        :name => name,
                        :port => port,
                        :proto => proto
                    })
            end

            def parse_records(xm_file)
                require "rexml/document"
                file = File.new(xm_file)
                doc = REXML::Document.new(file)
                doc.elements.each("records/record") do |e|
                    if e.elements['type'].text.strip =~ /PTR|^[A]$|AAAA/
                        report_host(e.elements['address'].text.strip)
                        
                        # Since several hosts can be tied to one IP, specially those that are vhosts
                        # or are behind a balancer the names are saved as notes.
                        framework.db.report_note({
                                :host => e.elements['address'].text.strip,
                                :type => "dns.info",
                                :data =>"A #{e.elements['name'].text.strip}",
                            })

                    elsif e.elements['type'].text.strip =~ /NS/
                        report_host(e.elements['address'].text.strip)
                        report_service("dns", "udp", 53, e.elements['address'].text.strip)
                        framework.db.report_note({
                                :host => e.elements['address'].text.strip,
                                :port => 53,
                                :proto => "udp",
                                :ntype => "dns.info",
                                :data =>"NS #{e.elements['target'].text.strip} "
                            })
         
                    elsif e.elements['type'].text.strip =~ /SOA/
                        report_host(e.elements['address'].text.strip)
                        report_service("dns", "udp", 53, e.elements['address'].text.strip)
                        framework.db.report_note({
                                :host => e.elements['address'].text.strip,
                                :port => 53,
                                :proto => "udp",
                                :type => "dns.info",
                                :data =>"NS #{e.elements['mname'].text.strip} "
                            })

                    elsif e.elements['type'].text.strip =~ /MX/
                        report_host(e.elements['address'].text.strip)
                        report_service("smtp", "tcp", 25, e.elements['address'].text.strip)
                        framework.db.report_note({
                                :host => e.elements['address'].text.strip,
                                :port => 25,
                                :proto => "tcp",
                                :type => "dns.info",
                                :data =>"MX #{e.elements['exchange'].text.strip} "
                            })

                    elsif e.elements['type'].text.strip =~ /SRV/
                        srv_info = []
                        srv_info = e.elements['name'].text.strip.scan(/^_(\S*)\._(tcp|udp|tls)\./)[0]
                        port = e.elements['port'].text.strip.to_i
                        if srv_info[1] == "tls"
                            proto = "tcp"
                        else
                            proto = srv_info[1]
                        end
                        report_host(e.elements['address'].text.strip)
                        report_service(srv_info[0], proto, port, e.elements['address'].text.strip)
                        framework.db.report_note({
                                :host => e.elements['address'].text.strip,
                                :port => port,
                                :proto => proto,
                                :type => "dns.info",
                                :data =>"SRV #{e.elements['target'].text.strip} "
                            })
     
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