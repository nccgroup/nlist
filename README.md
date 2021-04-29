# nList
An Nmap script to produce target lists for use with various tools.

## Installation
For the script to be run by default as part of all script scans (`-sC`), it will need to be saved in the `scripts` subdirectory of the Nmap data directory along with an `nlist.conf` file.

A `.nlist` file placed in the user's home directory will be used instead of the default `nlist.conf` file if another configuration file is not specified using the `nlist.config` argument. 

## Usage
Works best when run as part of a version scan (`-sV`).
<pre>
nmap [-sV] --script nlist [--script-args nlist.config=&lt;config_file&gt;,nlist.ignorehome,nlist.outdir=&lt;output_directory&gt;,nlist.overwrite] [-p-] &lt;target&gt;

-- nlist.config=&lt;config_file&gt;: 		nList configuration file
-- nlist.ignorehome: 				If specified, the '.nlist' configuration file in the user's home directory is ignored
-- nlist.outdir=&lt;output_directory&gt;: Output directory to write list files to ('./target_lists' by default)
-- nlist.overwrite: 				If specified, existing output files are overwritten
</pre>
All arguments override settings specified in config files!

## Configuration
Configuration files must follow the same structure as the `nlist.conf` file provided in this repository. It is advised that you familiarise yourself with this file before attempting to write your own configuration files.

Configuration files can contain the following options:

- `overwrite`: A Boolean value that specifies whether to overwrite existing output files (`true`) or append to them (`false`)
- `output_directory`: A string containing the directory in which to save any output files (will be created if it does not already exist)
- `use_default_rules`: A Boolean value that specifies whether to use the default rules defined in the `nlist.conf` file as well as the rules defined in this configuration file (`true`) or not (`false`)
- `use_home_rules`: A Boolean value that specifies whether to use the rules defined in the `.nlist` file in the user's home directory as well as the rules defined in this configuration file (`true`) or not (`false`)
- `output_files`: An array of specifications for each output file the script should generate (see subsection below for details)

### `output_files` Specifications
Each `output_files` specification is made up of the following options:

- `name`: A string containing the path to the output file
- `rules`: An array of rules that should be used to determine the contents of the file (see subsection below for details)
- `output_format`: An array specifying the format each line in the file should take (see subsection below for details)

#### `rules` Rules
Only one of the rules specified for an output file needs to be met for a port to be included in the output file (subsequent rules for the output file will be skipped for that port)!

Rules can be made up of a combination of the following criteria:

- `port_protocol`: An array containing acceptable port protocols (`tcp` and/or `udp`)
- `port_number`: An array containing acceptable port numbers
- `service`: An array containing acceptable services (not case sensitive)
- `service_type`: An array containing acceptable service types (currently only `http` and `ssl/tls` are valid values)

#### `output_format` Format
The first string in this array should be a format string containing `%s` where subsequent values should appear (these will appear in the order they are specified in). The following strings can be any combination of the following values:

- `ip`: The IP address of the host
- `port_number`: The port number
- `port_protocol`: The port protocol (`tcp` or `udp`)
- `service`: The service running on the port

You must specify the same number of values as there are occurrences of `%s` in your format string!
Literal `%` characters will need to be backslash escaped (`\%`)! 
