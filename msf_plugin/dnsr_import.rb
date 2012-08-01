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
					"import_dnsrecon_xml" => "Import DNSRecon XML output file.",
					"import_dnsrecon_csv" => "Import DNSRecon CSV output file."
				}
			end

			# Method for adding a host
			def report_host(ip)
				print_good("Importing host #{ip}")
				framework.db.report_host({:host => ip})
			end

			# Method for adding a service
			def report_service(name, proto, port, target)
				print_good("Importing service #{name} for host #{target}")
				framework.db.report_service({
						:host  => target,
						:name  => name,
						:port  => port,
						:proto => proto
					})
			end

			# Method for parsing and importing the XML file
			def xml_import(xm_file)
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
							srv_info = node.attribute('name').strip.scan(/^_([A-Za-z0-9_-]*)\._(tcp|udp|tls)\./)[0]
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

			# XML Import command
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
						xml_import(xml_file)
				end

			end

			# Tab completion for the XML import command
			def cmd_import_dnsrecon_xml_tabs(str, words)
				tab_complete_filenames(str, words)
			end

			# Method for parsing and importing the XML file
			def csv_import(csv_file)
				require "csv"
				CSV.foreach(csv_file) do |row|

					case row[0]

					when /PTR|^[A]$|AAAA/
						report_host(row[2])

						# Since several hosts can be tied to one IP, specially those that are vhosts
						# or are behind a balancer the names are saved as notes.
						framework.db.report_note({
								:host  => row[2],
								:ntype => "dns.info",
								:data  => "A #{row[1]}",
								:update => :unique_data
							})

					when /NS/
						report_host(row[2])
						report_service("dns", "udp", 53, row[2])
						framework.db.report_note({
								:host  => row[2],
								:port  => 53,
								:proto => "udp",
								:ntype => "dns.info",
								:data  => "NS #{row[1]}"
							})

					when /SOA/
						report_host(row[2])
						report_service("dns", "udp", 53, row[2])
						framework.db.report_note({
								:host  => row[2],
								:port  => 53,
								:proto => "udp",
								:type  => "dns.info",
								:data  => "NS #{row[1]}"
							})

					when /MX/
						report_host(row[2])
						report_service("smtp", "tcp", 25, row[2])
						framework.db.report_note({
								:host  => row[2],
								:port  => 25,
								:proto => "tcp",
								:type  => "dns.info",
								:data  => "MX #{row[1]}"
							})

					when /SRV/
						srv_info = []
						srv_info = row[1].strip.scan(/^_(\S*)\._(tcp|udp|tls)\./)[0]
						port = row[4].strip.to_i
						if srv_info[1] == "tls"
							proto = "tcp"
						else
							proto = srv_info[1]
						end
						report_host(row[2])
						report_service(srv_info[0], proto, port, row[2])
						framework.db.report_note({
								:host  => row[2],
								:port  => port,
								:proto => proto,
								:type  => "dns.info",
								:data  => "SRV #{row[3]}"
							})
					end
				end
			end

			# CSV Import command
			def cmd_import_dnsrecon_csv(*args)
				# Define options
				opts = Rex::Parser::Arguments.new(
					"-f"   => [ true,	"CSV file to import."],
					"-h"   => [ false,  "Command Help"]
				)

				# set variables for options
				csv_file = ""

				# Parse options
				opts.parse(args) do |opt, idx, val|
					case opt
					when "-f"
						csv_file = val

					when "-h"
						print_line(opts.usage)
						return
					end
				end

				if not ::File.exists?(csv_file)
						print_error "CSV File does not exists!"
						return
				else
						csv_import(csv_file)
				end

			end

			# Tab completion for the CSV import command
			def cmd_import_dnsrecon_csv_tabs(str, words)
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