import datetime
import os
import subprocess
import re
import json
import socket
import time
import glob
from zoneinfo import ZoneInfo
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# Try to import optional dependencies
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("Warning: requests module not found. Some functions may not work.")

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False
    print("Warning: BeautifulSoup not found. Some functions may not work.")

# Google ADK imports
try:
    from google.adk.agents import Agent
    from google.adk.models.lite_llm import LiteLlm
    from google.adk.sessions import InMemorySessionService
    from google.adk.runners import Runner
    from google.genai import types
    HAS_GOOGLE_ADK = True
except ImportError:
    HAS_GOOGLE_ADK = False
    print("Warning: Google ADK not found. Agent functionality may not work.")

def handle_results(result_data: dict, function_name: str, target_name: str = "", display_results: Optional[bool] = None, max_display_lines: int = 50):
    """
    Standardized result handling for all reconnaissance functions.
    
    Args:
        result_data: Dictionary containing the results to process
        function_name: Name of the function (for file naming)
        target_name: Target name/domain (for file naming)
        display_results: True to show all, False to hide, None to ask user if >50 lines
        max_display_lines: Maximum lines to show before asking user
    
    Returns:
        Dictionary with standardized result structure
    """
    # Generate timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create results directory
    results_dir = f"{function_name}_results"
    os.makedirs(results_dir, exist_ok=True)
    
    # Generate file name
    if target_name:
        safe_target = re.sub(r'[^\w\-_.]', '_', target_name)
        filename = f"{results_dir}/{function_name}_{safe_target}_{timestamp}.json"
    else:
        filename = f"{results_dir}/{function_name}_{timestamp}.json"
    
    # Always save results to file
    try:
        with open(filename, 'w') as f:
            json.dump(result_data, f, indent=2)
        result_data["saved_to"] = filename
    except Exception as e:
        result_data["file_save_error"] = str(e)
    
    # Handle result display logic
    if display_results is None:
        # Count lines in main result data (estimate)
        main_results = []
        for key, value in result_data.items():
            if isinstance(value, list) and key in ['subdomains', 'urls', 'broken_links', 'social_links', 'ipv4_ranges', 'ipv6_ranges', 'discovered_urls', 'extracted_urls', 'matches', 'results', 'swagger_results', 'postman_results']:
                main_results.extend(value)
        
        if len(main_results) > max_display_lines:
            result_data["display_note"] = f"Results contain {len(main_results)} items. Results saved to {filename}. To display results, re-run with display_results=True or specify max_display_lines."
            # Remove large result arrays from display
            for key in ['subdomains', 'urls', 'broken_links', 'social_links', 'ipv4_ranges', 'ipv6_ranges', 'discovered_urls', 'extracted_urls', 'matches', 'exact_matches', 'subdomain_matches', 'results', 'swagger_results', 'postman_results']:
                if key in result_data and isinstance(result_data[key], list):
                    if len(result_data[key]) > max_display_lines:
                        result_data[f"{key}_count"] = len(result_data[key])
                        result_data[f"{key}_preview"] = result_data[key][:5]  # Show first 5 items
                        del result_data[key]
    elif display_results is False:
        # Hide results but keep metadata
        result_data["display_note"] = f"Results hidden by request. Results saved to {filename}."
        for key in ['subdomains', 'urls', 'broken_links', 'social_links', 'ipv4_ranges', 'ipv6_ranges', 'discovered_urls', 'extracted_urls', 'matches', 'exact_matches', 'subdomain_matches', 'results', 'swagger_results', 'postman_results']:
            if key in result_data and isinstance(result_data[key], list):
                result_data[f"{key}_count"] = len(result_data[key])
                del result_data[key]
    # If display_results is True, show everything as-is
    
    return result_data

def get_ip_ranges(asn: str, display_results: Optional[bool] = None) -> dict:
    """
    Collect IPv4 and IPv6 ranges for a given ASN from RIPEstat, ipinfo.io, and bgp.he.net.
    """
    if not HAS_REQUESTS:
        return {
            "status": "error",
            "asn": asn,
            "error_message": "requests module is required for IP range discovery. Please install: pip install requests"
        }
    def get_from_ripestat(asn):
        try:
            url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
            res = requests.get(url, timeout=10)
            data = res.json()
            prefixes = data.get("data", {}).get("prefixes", [])
            ipv4 = [p['prefix'] for p in prefixes if p.get('family') == 4]
            ipv6 = [p['prefix'] for p in prefixes if p.get('family') == 6]
            return ipv4, ipv6
        except Exception as e:
            return [], []

    def get_from_ipinfo(asn):
        try:
            url = f"https://ipinfo.io/{asn}"
            res = requests.get(url, timeout=10)
            text = res.text
            ipv4 = re.findall(r'\d+\.\d+\.\d+\.\d+/\d+', text)
            return ipv4, []
        except Exception as e:
            return [], []

    def get_from_bgphe(asn):
        try:
            url = f"https://bgp.he.net/{asn}#_prefixes"
            res = requests.get(url, timeout=10)
            soup = BeautifulSoup(res.text, "html.parser")
            links = soup.select('a[href^="/net/"]')
            ranges = [a.text.strip() for a in links if '/' in a.text]
            ipv4 = [ip for ip in ranges if ':' not in ip]
            ipv6 = [ip for ip in ranges if ':' in ip]
            return ipv4, ipv6
        except Exception as e:
            return [], []

    def dedupe(lst):
        return sorted(set(lst))

    ipv4_total, ipv6_total = [], []
    for method in (get_from_ripestat, get_from_ipinfo, get_from_bgphe):
        ipv4, ipv6 = method(asn)
        ipv4_total.extend(ipv4)
        ipv6_total.extend(ipv6)

    result = {
        "asn": asn,
        "ipv4_ranges": dedupe(ipv4_total),
        "ipv6_ranges": dedupe(ipv6_total),
        "status": "success",
        "total_ipv4_ranges": len(dedupe(ipv4_total)),
        "total_ipv6_ranges": len(dedupe(ipv6_total))
    }
    
    return handle_results(result, "get_ip_ranges", asn, display_results)

def run_subdomain_tool(domain: str, tool: str, resolver_file: Optional[str] = None, wordlist_file: Optional[str] = None) -> list:
    """
    Run a specific subdomain enumeration tool.
    
    Args:
        domain: The target domain
        tool: The tool to use (subfinder, skanuvaty, bbot, csprecongo, shosubgo, scilla)
        resolver_file: Optional resolver file path
        wordlist_file: Optional wordlist file path (defaults to "subdomain_wordlist.txt" for skanuvaty)
    
    Returns:
        List of discovered subdomains, or empty list if tool fails or is not available
    """
    output_dir = "subdomain_results"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{tool}_subdomains.txt")
    
    # Create resolver file if not provided
    if resolver_file is None:
        resolver_file = os.path.join(output_dir, "resolvers.txt")
        if not os.path.exists(resolver_file):
            with open(resolver_file, "w") as res_out:
                res_out.write("8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n9.9.9.9\n149.112.112.112\n")
    
    try:
        if tool == "subfinder":
            cmd = ["subfinder", "-d", domain, "-o", output_file]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            
        elif tool == "skanuvaty":
            """
            skanuvaty - Fast subdomain scanner using DNS queries
            Command syntax: skanuvaty --target <domain> --concurrency <num> --subdomains-file <wordlist>
            Optional: --dns <resolver:port> for custom DNS resolver
            """
            # skanuvaty - Fast subdomain scanner with comprehensive error handling
            try:
                # Step 1: Validate and prepare wordlist file
                wordlist_path = wordlist_file if wordlist_file else "subdomain_wordlist.txt"
                
                # Check file existence
                if not os.path.exists(wordlist_path):
                    print(f"Error: Wordlist file not found: {wordlist_path}")
                    print(f"Create a wordlist file with: echo -e 'www\\napi\\nmail\\nftp\\ndev\\ntest\\nstaging\\nadmin\\napp\\ncdn' > {wordlist_path}")
                    return []
                
                # Validate file content
                try:
                    with open(wordlist_path, 'r', encoding='utf-8') as f:
                        content = f.read().strip()
                        if not content:
                            print(f"Error: Wordlist file is empty: {wordlist_path}")
                            print("Add subdomain names to the wordlist file, one per line")
                            return []
                        
                        lines = [line.strip() for line in content.split('\n') if line.strip()]
                        if len(lines) < 1:
                            print(f"Error: Wordlist file has no valid entries: {wordlist_path}")
                            print("Ensure wordlist contains subdomain names, one per line")
                            return []
                        
                        print(f"Using wordlist: {wordlist_path} ({len(lines)} entries)")
                        
                except (PermissionError, UnicodeDecodeError) as e:
                    print(f"Error reading wordlist file: {str(e)}")
                    print(f"Check file permissions and encoding for: {wordlist_path}")
                    return []
                
                # Step 2: Build command with proper syntax
                clean_domain = domain.replace('http://', '').replace('https://', '').strip('/')
                cmd = ["skanuvaty", "--target", clean_domain, "--concurrency", "16", "--subdomains-file", wordlist_path, "-o", output_file]
                
                # Step 3: Add DNS resolver if provided
                if resolver_file and os.path.exists(resolver_file):
                    try:
                        with open(resolver_file, 'r') as f:
                            content = f.read().strip()
                            if content:
                                for line in content.split('\n'):
                                    resolver = line.strip()
                                    if resolver and not resolver.startswith('#'):
                                        # Ensure proper format (IP:port)
                                        if ':' not in resolver:
                                            resolver = f"{resolver}:53"
                                        
                                        # Basic IP validation
                                        ip_part = resolver.split(':')[0]
                                        try:
                                            parts = ip_part.split('.')
                                            if len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts):
                                                cmd.extend(["--dns", resolver])
                                                print(f"Using DNS resolver: {resolver}")
                                                break
                                        except (ValueError, AttributeError):
                                            continue
                    except Exception as e:
                        print(f"Warning: Could not read resolver file {resolver_file}: {str(e)}")
                
                print(f"Command: {' '.join(cmd)}")
                
                # Step 4: Execute command with timeout and error handling
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=600,  # 10 minute timeout
                    check=False   # Don't raise on non-zero exit
                )
                
                # Handle different exit codes
                if result.returncode == 0:
                    # Success - skanuvaty wrote directly to output_file with -o flag
                    print(f"skanuvaty scan completed successfully")
                    # The function will fall through to the standard file reading logic at the end
                    
                elif result.returncode == 1:
                    print(f"skanuvaty execution failed - no subdomains found or invalid target")
                    if result.stderr:
                        print(f"Error details: {result.stderr.strip()}")
                    print("Verify domain exists and wordlist contains valid subdomain prefixes")
                    return []
                else:
                    print(f"skanuvaty failed with exit code {result.returncode}")
                    if result.stderr:
                        print(f"Error details: {result.stderr.strip()}")
                    print("Check command syntax and tool installation")
                    return []
                    
            except subprocess.TimeoutExpired:
                print("skanuvaty scan timed out after 10 minutes")
                print("Try reducing concurrency (--concurrency 8) or using a smaller wordlist")
                return []
            except FileNotFoundError:
                print("skanuvaty command not found")
                print("Install skanuvaty: pip install skanuvaty")
                print("Verify installation: skanuvaty --help")
                return []
            except Exception as e:
                print(f"Unexpected error running skanuvaty: {str(e)}")
                print("Check skanuvaty installation and system permissions")
                return []
            
        elif tool == "bbot":
            try:
                # Generate unique scan name with timestamp to avoid conflicts
                scan_name = f"{domain.replace('.', '_')}_{int(time.time())}"
                
                # Use proper bbot command with current best practices
                cmd = [
                    "bbot", 
                    "-t", domain, 
                    "-p", "subdomain-enum",  # Use preset instead of -f flag
                    "-o", output_dir,
                    "-n", scan_name,  # Specify scan name
                    "--allow-deadly",
                    "-v"  # Verbose output for better debugging
                ]
                
                print(f"Running bbot command: {' '.join(cmd)}")
                print(f"Scan name: {scan_name}")
                
                # Use Popen with proper interactive handling
                process = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,  # Line buffered
                    universal_newlines=True,
                    env=os.environ.copy()  # Inherit environment variables
                )
                
                # Handle interactive prompts immediately
                try:
                    # Send newline immediately to handle any interactive prompts
                    if process.stdin:
                        process.stdin.write("\n")
                        process.stdin.flush()
                        process.stdin.close()
                except (BrokenPipeError, OSError, ValueError) as e:
                    print(f"Warning: Could not send input to bbot process: {e}")
                
                # Monitor process with timeout
                try:
                    stdout, stderr = process.communicate(timeout=3600)  # 1 hour timeout
                    print(f"bbot completed with return code: {process.returncode}")
                    
                    if stdout:
                        print(f"bbot stdout (last 500 chars): {stdout[-500:]}")
                    if stderr:
                        print(f"bbot stderr (last 500 chars): {stderr[-500:]}")
                        
                except subprocess.TimeoutExpired:
                    print("bbot execution timed out after 1 hour, terminating...")
                    process.kill()
                    try:
                        stdout, stderr = process.communicate(timeout=30)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        stdout, stderr = "", ""
                    print("bbot process terminated due to timeout")
                    return []
                
                # Check if process completed successfully
                if process.returncode != 0:
                    print(f"bbot failed with return code {process.returncode}")
                    if stderr:
                        print(f"Error output: {stderr}")
                    return []
                
                # Wait for bbot to fully complete and write all files
                print("Waiting for bbot to fully complete and write output files...")
                time.sleep(30)  # Wait for bbot to finish
                
                # Log that bbot scan completed (but don't read/return results)
                expected_subdomain_file = os.path.join(output_dir, scan_name, "subdomains.txt")
                print(f"bbot scan completed, results should be in: {expected_subdomain_file}")
                
                # Always return empty list regardless of actual results
                print("bbot scan completed")
                return []
                    
            except FileNotFoundError:
                print("bbot command not found. Please install bbot: pip install bbot")
                return []
            except PermissionError as e:
                print(f"Permission denied running bbot: {e}")
                return []
            except subprocess.SubprocessError as e:
                print(f"Subprocess error running bbot: {e}")
                import traceback
                traceback.print_exc()
                return []
            except Exception as e:
                print(f"Unexpected error running bbot: {e}")
                import traceback
                traceback.print_exc()
                return []
            
        elif tool == "csprecongo":
            # CspReconGo requires URL format and uses go run command
            target_url = domain
            if not target_url.startswith(("http://", "https://")):
                target_url = f"https://{domain}"
            
            cmd = ["go", "run", "CspReconGo.go", target_url]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # CspReconGo outputs to stdout, so we need to save it to our output file
            if result.stdout:
                with open(output_file, "w") as out_file:
                    out_file.write(result.stdout)
            
            # Check if the command was successful
            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, cmd)
            
        elif tool == "shosubgo":
            # shosubgo requires Shodan API key and uses go run command
            api_key = None
            api_key_file = "shodan_api.txt"
            
            # Check if API key file exists
            if os.path.exists(api_key_file):
                try:
                    with open(api_key_file, "r") as f:
                        api_key = f.read().strip()
                except Exception:
                    pass
            
            # If no API key found, raise error with instructions
            if not api_key:
                raise FileNotFoundError(
                    f"Shodan API key required for shosubgo. "
                    f"Please create {api_key_file} file with your API key. "
                    f"Get your free API key from: https://account.shodan.io/"
                )
            
            # Run shosubgo with correct syntax
            cmd = ["shosubgo", "-d", domain, "-s", api_key]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # shosubgo outputs to stdout, so we need to save it to our output file
            if result.stdout:
                with open(output_file, "w") as out_file:
                    out_file.write(result.stdout)
            
            # Check if the command was successful
            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, cmd)
            
        elif tool == "scilla":
            # scilla is a DNS subdomain enumeration tool with wordlist support
            wordlist_file = "subdomain_wordlist.txt"
            if not os.path.exists(wordlist_file):
                return {
                    "status": "error",
                    "tool": tool,
                    "domain": domain,
                    "error_message": f"Required wordlist file not found: {wordlist_file}. scilla requires a wordlist file to function.",
                    "suggestion": "Create a wordlist file with subdomains to test, one per line (e.g., www, mail, ftp, api, dev, test, staging, admin)."
                }
            
            cmd = ["scilla", "subdomain", "-w", "subdomain_wordlist.txt", "-target", domain, "-ot", output_file]
            
            # Add resolver if provided (extract first resolver IP without port)
            if resolver_file and os.path.exists(resolver_file):
                try:
                    with open(resolver_file, "r") as res_file:
                        first_resolver = res_file.readline().strip()
                        if first_resolver:
                            # Remove port if present (e.g., 8.8.8.8:53 -> 8.8.8.8)
                            resolver_ip = first_resolver.split(':')[0]
                            cmd.extend(["-dns", resolver_ip])
                except Exception:
                    pass  # Let scilla use default resolver
            
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        
        # Read subdomains from the output file
        print(f"Looking for output file: {output_file}")
        if os.path.exists(output_file):
            print(f"Output file exists, reading...")
            with open(output_file, "r") as file:
                subdomains = [line.strip() for line in file if line.strip()]
                print(f"Found {len(subdomains)} subdomains from {tool}")
                return subdomains
        else:
            print(f"Output file does not exist: {output_file}")
            # Check if any files were created in the output directory
            if os.path.exists(output_dir):
                files = os.listdir(output_dir)
                print(f"Files in output directory: {files}")
        return []
        
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error running {tool}: {e}")
        return []
    except Exception as e:
        print(f"Unexpected error running {tool}: {e}")
        return []

def get_subdomains(domain: str, tools: str = "subfinder", resolver_file: Optional[str] = None, display_results: Optional[bool] = None, wordlist_file: Optional[str] = None) -> dict:
    """
    Enumerate subdomains for a given domain using specified tools concurrently.
    
    Args:
        domain: The target domain to enumerate subdomains for
        tools: Comma-separated list of tools to use (subfinder,skanuvaty,bbot,csprecongo,shosubgo,scilla) or "all"
        resolver_file: Optional resolver file path
        wordlist_file: Optional wordlist file path (for skanuvaty tool, defaults to "subdomain_wordlist.txt")
    
    Returns:
        Dictionary containing discovered subdomains
    """
    # Determine which tools to run
    available_tools = ["subfinder", "skanuvaty", "bbot", "csprecongo", "shosubgo", "scilla"]
    selected_tools = []
    
    if tools.lower() == "all":
        selected_tools = available_tools
    else:
        selected_tools = [t.strip().lower() for t in tools.split(",") if t.strip()]
        # Validate tool names
        for tool in selected_tools:
            if tool not in available_tools:
                return {
                    "status": "error",
                    "domain": domain,
                    "error_message": f"Invalid tool specified: {tool}. Available tools: {', '.join(available_tools)}"
                }
    
    # Run tools concurrently
    all_subdomains = []
    tool_results = {}
    failed_tools = []
    
    def run_tool_with_error_handling(tool):
        try:
            print(f"Running {tool} on {domain}...")
            subdomains = run_subdomain_tool(domain, tool, resolver_file, wordlist_file)
            print(f"Tool {tool} returned {len(subdomains)} subdomains: {subdomains[:5] if subdomains else 'None'}")
            return tool, subdomains, None
        except Exception as e:
            print(f"Tool {tool} failed with error: {str(e)}")
            return tool, [], str(e)
    
    # Use ThreadPoolExecutor for concurrent execution
    with ThreadPoolExecutor(max_workers=min(len(selected_tools), 4)) as executor:
        # Submit all tasks
        future_to_tool = {executor.submit(run_tool_with_error_handling, tool): tool for tool in selected_tools}
        
        # Process completed tasks
        for future in as_completed(future_to_tool):
            tool, subdomains, error = future.result()
            if error:
                failed_tools.append(f"{tool}: {error}")
                tool_results[tool] = 0
            else:
                all_subdomains.extend(subdomains)
                tool_results[tool] = len(subdomains)
    
    # Deduplicate and sort subdomains
    unique_subdomains = sorted(set(all_subdomains))
    
    # Save consolidated results to main file
    consolidated_file = f"{domain}_all_subdomains.txt"
    try:
        with open(consolidated_file, "w") as outfile:
            for subdomain in unique_subdomains:
                outfile.write(f"{subdomain}\n")
    except Exception as e:
        print(f"Error saving consolidated results: {e}")
    
    result = {
        "status": "success" if unique_subdomains else "partial" if failed_tools else "error",
        "domain": domain,
        "subdomains": unique_subdomains,
        "total_subdomains": len(unique_subdomains),
        "tool_results": tool_results,
        "tools_used": selected_tools
    }
    
    if failed_tools:
        result["failed_tools"] = failed_tools
    
    if unique_subdomains:
        result["message"] = f"Found {len(unique_subdomains)} unique subdomains using {len(selected_tools)} tools."
    else:
        result["error_message"] = f"No subdomains found for {domain} using the selected tools."
    
    return handle_results(result, "get_subdomains", domain, display_results)

def get_archive_urls(domain: str, tools: str = "waymore", display_results: Optional[bool] = None) -> dict:
    """
    Find URLs for a domain using various URL discovery tools.
    
    Args:
        domain: The target domain to search for URLs
        tools: Comma-separated list of tools to use (waymore,gau,waybackurls) or "all"
    
    Returns:
        Dictionary containing discovered URLs
    """
    # Determine which tools to run
    available_tools = ["waymore", "gau", "waybackurls"]
    selected_tools = []
    
    if tools.lower() == "all":
        selected_tools = available_tools
    else:
        selected_tools = [t.strip().lower() for t in tools.split(",") if t.strip()]
        # Validate tool names
        for tool in selected_tools:
            if tool not in available_tools:
                return {
                    "status": "error",
                    "domain": domain,
                    "error_message": f"Invalid tool specified: {tool}. Available tools: {', '.join(available_tools)}"
                }
    
    # Create output directory
    output_dir = "archive_urls_results"
    os.makedirs(output_dir, exist_ok=True)
    
    # Run each tool and collect URLs
    all_urls = []
    tool_results = {}
    
    for tool in selected_tools:
        try:
            print(f"Running {tool} on {domain}...")
            
            # Run the appropriate tool
            if tool == "waymore":
                urls = _run_waymore(domain, output_dir)
            elif tool == "gau":
                urls = _run_gau(domain, output_dir)
            elif tool == "waybackurls":
                urls = _run_waybackurls(domain, output_dir)
            
            # Add to collection and track count
            all_urls.extend(urls)
            tool_results[tool] = len(urls)
            
        except Exception as e:
            print(f"Error running {tool}: {e}")
            tool_results[tool] = f"Error: {str(e)}"
    
    # Deduplicate and sort URLs
    unique_urls = sorted(set(all_urls))
    
    # Save consolidated results to main file
    output_file = os.path.join(output_dir, f"all_urls_{domain}.txt")
    with open(output_file, "w") as outfile:
        for url in unique_urls:
            outfile.write(f"{url}\n")
    
    result = {
        "status": "success" if unique_urls else "error",
        "domain": domain,
        "urls": unique_urls,
        "total_urls": len(unique_urls),
        "tool_results": tool_results,
        "stdout_output": len(result.stdout.split("\n"))
    }
    
    if unique_urls:
        result["message"] = f"Found {len(unique_urls)} unique URLs using {len(selected_tools)} tools. Results saved to {output_file}"
    else:
        result["error_message"] = f"No URLs found for {domain} using the selected tools."
    
    return handle_results(result, "get_archive_urls", domain, display_results)

def _run_waymore(domain: str, output_dir: str) -> list:
    """
    Run waymore to find URLs from various sources including Wayback Machine, CommonCrawl, and more.
    """
    # Create tool-specific output directory
    waymore_dir = "waymore_output"
    os.makedirs(waymore_dir, exist_ok=True)
    
    # Define output file paths
    output_file = os.path.join(waymore_dir, f"{domain}.txt")
    copy_file = os.path.join(output_dir, f"waymore_{domain}.txt")
    
    # Check if waymore is installed
    try:
        subprocess.run(["waymore", "-h"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("waymore is not installed or not in PATH")
        return []
    
    # Run waymore command with correct syntax
    cmd = ["waymore", "-i", domain, "-oU", output_file]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            print(f"waymore command failed: {result.stderr}")
            return []
        
        # Read the output file
        if not os.path.exists(output_file):
            return []
        
        with open(output_file, "r", encoding="utf-8") as file:
            urls = [url.strip() for url in file if url.strip()]
        
        # Copy results to the unified output directory
        with open(copy_file, "w", encoding="utf-8") as file:
            for url in urls:
                file.write(f"{url}\n")
        
        return urls
        
    except subprocess.TimeoutExpired:
        print("waymore command timed out after 5 minutes")
        return []
    except Exception as e:
        print(f"Unexpected error running waymore: {str(e)}")
        return []


def _run_gau(domain: str, output_dir: str) -> list:
    """
    Run gau (getallurls) to find URLs from various web archives.
    """
    # Define output file path
    output_file = os.path.join(output_dir, f"gau_{domain}.txt")
    
    # Check if gau is installed
    try:
        subprocess.run(["gau", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("gau is not installed or not in PATH")
        return []
    
    # Run gau command
    cmd = ["gau", domain, "--o", output_file]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        if result.returncode != 0:
            # Try alternate syntax for older versions
            cmd = ["gau", domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode != 0:
                print(f"gau command failed: {result.stderr}")
                return []
            
            # Save the output manually for older versions
            with open(output_file, "w", encoding="utf-8") as file:
                file.write(result.stdout)
        
        # Read the output file
        if not os.path.exists(output_file):
            # For older versions that output to stdout
            urls = [url.strip() for url in result.stdout.splitlines() if url.strip()]
        else:
            with open(output_file, "r", encoding="utf-8") as file:
                urls = [url.strip() for url in file if url.strip()]
        
        return urls
        
    except subprocess.TimeoutExpired:
        print("gau command timed out after 10 minutes")
        return []
    except Exception as e:
        print(f"Unexpected error running gau: {str(e)}")
        return []

def _run_waybackurls(domain: str, output_dir: str) -> list:
    """
    Run waybackurls to find URLs from the Wayback Machine.
    """
    # Define output file path
    output_file = os.path.join(output_dir, f"waybackurls_{domain}.txt")
    
    # Check if waybackurls is installed
    try:
        subprocess.run(["waybackurls", "-h"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("waybackurls is not installed or not in PATH")
        return []
    
    # Run waybackurls command
    cmd = ["waybackurls", domain]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        if result.returncode != 0:
            print(f"waybackurls command failed: {result.stderr}")
            return []
        
        # Save the output to file
        with open(output_file, "w", encoding="utf-8") as file:
            file.write(result.stdout)
        
        # Parse URLs from stdout
        urls = [url.strip() for url in result.stdout.splitlines() if url.strip()]
        
        return urls
        
    except subprocess.TimeoutExpired:
        print("waybackurls command timed out after 10 minutes")
        return []
    except Exception as e:
        print(f"Unexpected error running waybackurls: {str(e)}")
        return []

# Legacy function for backward compatibility
def waymore_check(domain: str) -> dict:
    """
    Legacy function that redirects to get_archive_urls with waymore as the tool.
    """
    return get_archive_urls(domain, "waymore")
def run_port_scan(target: str, ports: str = "top-1000", tool: str = "nmap") -> dict:
    """
    Perform port scanning on a target using a selected tool.
    
    Args:
        target: The IP address, domain, or file path containing targets (one per line)
        ports: Port specification - can be one of:
               - "top-1000" (default): Scan top 1000 ports
               - Comma-separated list of ports: "22,80,443,8080"
               - Range of ports: "1-1000"
               - File path containing ports (one per line)
        tool: The scanning tool to use - one of: "nmap" (default), "smap"
    
    Returns:
        Dictionary containing scan results with open ports and their services
    """
    try:
        # Validate the tool parameter
        available_tools = ["nmap", "smap"]
        if tool.lower() not in available_tools:
            return {
                "status": "error",
                "target": target,
                "error_message": f"Invalid tool specified: {tool}. Available tools: {', '.join(available_tools)}"
            }
        
        # Check if the selected tool is installed
        try:
            if tool == "nmap":
                subprocess.run(["nmap", "--version"], capture_output=True, check=True)
            elif tool == "smap":
                subprocess.run(["smap", "-h"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            return {
                "status": "error",
                "target": target,
                "tool": tool,
                "error_message": f"{tool} is not installed or not in PATH. Please install it first."
            }
        
        # Determine if target is a file path
        targets_list = []
        is_file_target = False
        if os.path.exists(target) and os.path.isfile(target):
            is_file_target = True
            with open(target, "r") as file:
                targets_list = [line.strip() for line in file if line.strip()]
            
            if not targets_list:
                return {
                    "status": "error",
                    "target": target,
                    "error_message": f"No valid targets found in file: {target}. The file exists but appears to be empty or contains no valid IP addresses/domains.",
                    "suggestion": "Ensure the file contains valid IP addresses or domains, one per line (e.g., 192.168.1.1, example.com)."
                }
        elif target.endswith('.txt') or '/' in target:
            # Target looks like a file path but doesn't exist
            return {
                "status": "error",
                "target": target,
                "error_message": f"Target file not found: {target}. Please ensure the file exists and contains IP addresses or domains (one per line).",
                "suggestion": "Create a file with IP addresses or domains to scan, one per line (e.g., 192.168.1.1, example.com), or provide a single target directly."
            }
        else:
            # Single target
            targets_list = [target]
        
        # Determine if ports parameter is a file path
        port_spec = ports
        if os.path.exists(ports) and os.path.isfile(ports):
            with open(ports, "r") as file:
                port_lines = [line.strip() for line in file if line.strip()]
                if port_lines:
                    port_spec = ",".join(port_lines)
        
        # Create directories for output if needed
        output_dir = f"{tool}_results"
        os.makedirs(output_dir, exist_ok=True)
        
        # Branch based on the selected tool
        if tool == "nmap":
            return _run_nmap_scan(targets_list, port_spec, output_dir)
        elif tool == "smap":
            return _run_smap_scan(targets_list, target if is_file_target else None, output_dir)
        
    except Exception as e:
        return {
            "status": "error",
            "target": target,
            "tool": tool,
            "error_message": f"Unexpected error during port scan: {str(e)}"
        }

def _run_nmap_scan(targets_list, port_spec, output_dir):
    """
    Helper function to run nmap scans.
    """
    # Prepare base nmap command
    base_cmd = ["nmap", "-T4"]  # Faster timing template
    
    # Handle port specification
    if port_spec == "top-1000":
        base_cmd.extend(["--top-ports", "1000"])
    else:
        base_cmd.extend(["-p", port_spec])
    
    # Add output format to base command
    base_cmd.extend(["-oG", "-"])  # Grepable output format to stdout
    
    # Store results for all targets
    all_results = []
    
    # Scan each target
    for current_target in targets_list:
        try:
            # Create command for this target
            cmd = base_cmd.copy()
            cmd.append(current_target)
            
            # Run nmap command
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                all_results.append({
                    "status": "error",
                    "target": current_target,
                    "error_message": f"nmap scan failed: {result.stderr}"
                })
                continue
            
            # Parse the output to extract open ports
            open_ports = []
            for line in result.stdout.splitlines():
                if "Ports:" in line:
                    ports_part = line.split("Ports:")[1].strip()
                    port_entries = ports_part.split(", ")
                    
                    for entry in port_entries:
                        parts = entry.split("/")
                        if len(parts) >= 3 and parts[1] == "open":
                            port_number = parts[0]
                            protocol = parts[2]
                            service = parts[4] if len(parts) > 4 else "unknown"
                            
                            open_ports.append({
                                "port": port_number,
                                "protocol": protocol,
                                "service": service
                            })
            
            # Run a more detailed scan on open ports to get service versions
            if open_ports:
                open_port_numbers = ",".join([p["port"] for p in open_ports])
                detailed_cmd = ["nmap", "-T4", "-sV", "-p", open_port_numbers, current_target]
                detailed_result = subprocess.run(detailed_cmd, capture_output=True, text=True, timeout=300)
                
                # Parse detailed output to update service information
                if detailed_result.returncode == 0:
                    for line in detailed_result.stdout.splitlines():
                        if "/tcp" in line or "/udp" in line:
                            parts = line.strip().split()
                            if len(parts) >= 3:
                                port_protocol = parts[0]
                                port_number = port_protocol.split("/")[0]
                                state = parts[1]
                                
                                if state == "open":
                                    service_info = " ".join(parts[2:])
                                    
                                    # Update existing port info
                                    for port in open_ports:
                                        if port["port"] == port_number:
                                            port["service_details"] = service_info
                                            break
            
            # Add result for this target
            all_results.append({
                "status": "success",
                "target": current_target,
                "timestamp": datetime.datetime.now().isoformat(),
                "open_ports": open_ports,
                "total_open_ports": len(open_ports),
                "message": f"Found {len(open_ports)} open ports on {current_target}"
            })
            
        except Exception as e:
            all_results.append({
                "status": "error",
                "target": current_target,
                "error_message": f"Error scanning {current_target}: {str(e)}"
            })
    
    # Determine total number of successful and failed scans
    successful_scans = sum(1 for r in all_results if r["status"] == "success")
    failed_scans = sum(1 for r in all_results if r["status"] == "error")
    total_open_ports = sum(r["total_open_ports"] for r in all_results if r["status"] == "success")
    
    # Prepare final result
    if len(targets_list) == 1:
        # If only one target, return its result directly
        return all_results[0]
    else:
        # For multiple targets, return a summary
        return {
            "status": "success",
            "timestamp": datetime.datetime.now().isoformat(),
            "scan_type": f"nmap port scan ({port_spec})",
            "tool": "nmap",
            "total_targets": len(targets_list),
            "successful_scans": successful_scans,
            "failed_scans": failed_scans,
            "total_open_ports": total_open_ports,
            "target_results": all_results,
            "message": f"Scanned {len(targets_list)} targets with nmap. Found {total_open_ports} open ports across {successful_scans} targets."
        }

def _run_smap_scan(targets_list, input_file, output_dir):
    """
    Helper function to run smap scans.
    """
    # If we don't have a file of targets already, create one
    if not input_file:
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        temp_targets_file = os.path.join(output_dir, f"smap_targets_{timestamp}.txt")
        with open(temp_targets_file, "w") as f:
            for target in targets_list:
                f.write(f"{target}\n")
        input_file = temp_targets_file
    
    # Define output file for smap
    output_file = os.path.join(output_dir, f"smap_{os.path.basename(input_file)}.json")
    
    # Run smap command
    cmd = ["smap", "-iL", input_file, "-oJ", output_file]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # 30 minutes timeout
        
        if result.returncode != 0:
            return {
                "status": "error",
                "file_path": input_file,
                "error_message": f"smap command failed: {result.stderr}"
            }
        
        # Read the output file
        if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
            return {
                "status": "success",
                "file_path": input_file,
                "tool": "smap",
                "results": [],
                "total_hosts": 0,
                "total_ports": 0,
                "message": "No results found with smap"
            }
        
        # Parse JSON results
        try:
            with open(output_file, "r") as file:
                smap_results = json.load(file)
        except json.JSONDecodeError:
            # If not valid JSON, read as text
            with open(output_file, "r") as file:
                smap_results = file.read()
                return {
                    "status": "error",
                    "file_path": input_file,
                    "error_message": f"Could not parse smap results as JSON. Raw output saved to {output_file}"
                }
        
        # Count statistics
        total_hosts = len(smap_results) if isinstance(smap_results, list) else 0
        total_ports = sum(len(host.get("ports", [])) for host in smap_results if isinstance(host, dict))
        
        # Read IPs from input file to get total count
        with open(input_file, "r") as file:
            ips = [line.strip() for line in file if line.strip()]
        
        return {
            "status": "success",
            "file_path": input_file,
            "timestamp": datetime.datetime.now().isoformat(),
            "tool": "smap",
            "results": smap_results,
            "total_hosts": total_hosts,
            "total_ports": total_ports,
            "stdout_output": len(result.stdout.split("\n")),
            "message": f"Scanned {len(ips)} IP addresses with smap. Found {total_ports} open ports across {total_hosts} hosts. Full results saved to {output_file}"
        }
        
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "file_path": input_file,
            "error_message": "smap command timed out after 30 minutes"
        }
    except Exception as e:
        return {
            "status": "error",
            "file_path": input_file,
            "error_message": f"Unexpected error during smap scan: {str(e)}"
        }

# Alias for backward compatibility
def port_scan(target: str, ports: str = "top-1000") -> dict:
    """
    Legacy function that redirects to run_port_scan with nmap as the tool.
    """
    return run_port_scan(target, ports, "nmap")

def smap_scan(file_path: str = "ips.txt") -> dict:
    """
    Legacy function that redirects to run_port_scan with smap as the tool.
    """
    return run_port_scan(file_path, "top-1000", "smap")

def resolve_subdomains(file_path: str = "subdomains.txt") -> dict:
    """
    Resolve subdomains from a file to their IP addresses and save the results to ips.txt.
    
    Args:
        file_path: Path to the file containing subdomains (one per line)
    
    Returns:
        Dictionary containing resolved IP addresses
    """
    try:
        if not os.path.exists(file_path):
            return {
                "status": "error",
                "file_path": file_path,
                "error_message": f"File not found: {file_path}. Please ensure the file exists and contains subdomains (one per line). You can create this file by running subdomain enumeration first.",
                "suggestion": "Run get_subdomains() to generate a subdomains file, or create the file manually with one subdomain per line."
            }
        
        # Read subdomains from file
        with open(file_path, "r") as file:
            subdomains = [line.strip() for line in file if line.strip()]
        
        if not subdomains:
            return {
                "status": "error",
                "file_path": file_path,
                "error_message": f"No subdomains found in file: {file_path}. The file exists but appears to be empty or contains no valid subdomains.",
                "suggestion": "Ensure the file contains valid subdomains, one per line (e.g., sub1.example.com, sub2.example.com)."
            }
        
        # Resolve each subdomain to its IP address
        resolved = []
        for subdomain in subdomains:
            try:
                ip = socket.gethostbyname(subdomain)
                resolved.append({"subdomain": subdomain, "ip": ip})
            except socket.gaierror:
                # Skip subdomains that cannot be resolved
                continue
        
        # Save resolved IPs to file
        with open("ips.txt", "w") as file:
            for item in resolved:
                file.write(f"{item['ip']}\n")
        
        return {
            "status": "success",
            "file_path": file_path,
            "resolved_count": len(resolved),
            "total_subdomains": len(subdomains),
            "resolved_ips": [item["ip"] for item in resolved],
            "output_file": "ips.txt",
            "message": f"Resolved {len(resolved)} out of {len(subdomains)} subdomains. IPs saved to ips.txt"
        }
        
    except Exception as e:
        return {
            "status": "error",
            "file_path": file_path,
            "error_message": f"Unexpected error: {str(e)}"
        }

def cloud_recon(search_domain: str, display_results: Optional[bool] = None) -> dict:
    """
    Download cloud provider domain/subdomain lists and search for matches.
    
    Args:
        search_domain: The domain/subdomain to search for in cloud provider lists
        display_results: Whether to display detailed results or just save them
    
    Returns:
        Dictionary containing search results and file locations
    """
    try:
        # Cloud providers and their SNI domain list URLs
        providers = {
            "amazon": "https://kaeferjaeger.gay/sni-ip-ranges/amazon/ipv4_merged_sni.txt",
            "digitalocean": "https://kaeferjaeger.gay/sni-ip-ranges/digitalocean/ipv4_merged_sni.txt", 
            "google": "https://kaeferjaeger.gay/sni-ip-ranges/google/ipv4_merged_sni.txt",
            "microsoft": "https://kaeferjaeger.gay/sni-ip-ranges/microsoft/ipv4_merged_sni.txt",
            "oracle": "https://kaeferjaeger.gay/sni-ip-ranges/oracle/ipv4_merged_sni.txt"
        }
        
        # Create output directory
        output_dir = "cloud_domains"
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate timestamp
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Download domain lists and save files
        saved_files = {}
        download_errors = []
        
        for provider, url in providers.items():
            filename = f"{provider}_{timestamp}.txt"
            filepath = os.path.join(output_dir, filename)
            
            try:
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                
                with open(filepath, 'w') as f:
                    f.write(response.text)
                
                saved_files[provider] = filepath
                
            except Exception as e:
                download_errors.append(f"{provider}: {str(e)}")
        
        # Search for user's search term in downloaded lists (grep-like functionality)
        matches = {}
        exact_matches = {}
        subdomain_matches = {}
        grep_matches = {}
        
        for provider, filepath in saved_files.items():
            try:
                with open(filepath, 'r') as f:
                    domains = [line.strip() for line in f if line.strip()]
                
                # Check for exact matches
                exact_found = [domain for domain in domains if domain == search_domain]
                if exact_found:
                    exact_matches[provider] = exact_found
                
                # Check for subdomain matches (domains ending with search_domain)
                subdomain_found = [domain for domain in domains if domain.endswith('.' + search_domain)]
                if subdomain_found:
                    subdomain_matches[provider] = subdomain_found
                
                # Check for grep-like matches (domains containing the search term)
                grep_found = [domain for domain in domains if search_domain.lower() in domain.lower() and domain not in exact_found and domain not in subdomain_found]
                if grep_found:
                    grep_matches[provider] = grep_found
                
                # Combine all matches for this provider
                all_provider_matches = list(set(
                    exact_matches.get(provider, []) + 
                    subdomain_matches.get(provider, []) + 
                    grep_matches.get(provider, [])
                ))
                if all_provider_matches:
                    matches[provider] = all_provider_matches
                    
            except Exception as e:
                download_errors.append(f"Error searching {provider}: {str(e)}")
        
        # Prepare result
        result = {
            "status": "success",
            "search_domain": search_domain,
            "timestamp": timestamp,
            "saved_files": saved_files,
            "total_matches": sum(len(m) for m in matches.values()),
            "providers_with_matches": len(matches),
            "matches": matches,
            "exact_matches": exact_matches,
            "subdomain_matches": subdomain_matches,
            "grep_matches": grep_matches,
            "message": f"Cloud domain search completed for '{search_domain}'. {len(saved_files)} files saved, {len(matches)} providers had matches."
        }
        
        if download_errors:
            result["download_errors"] = download_errors
        
        return handle_results(result, "cloud_recon", search_domain, display_results)
        
    except Exception as e:
        return {
            "status": "error",
            "search_domain": search_domain,
            "error_message": f"Unexpected error in cloud_recon: {str(e)}"
        }

def get_js_links(inputs: str, input_type: str = "auto", display_results: Optional[bool] = None) -> dict:
    """
    Extract URLs from JavaScript files using linkfinder with support for multiple input types.
    
    Args:
        inputs: Single string or list of strings containing JS files, URLs, or mixed
        input_type: Type of input - "js_file", "url", "mixed", or "auto" (auto-detect)
    
    Returns:
        Dictionary containing extracted URLs and processing results
    """
    try:
        # Check if linkfinder is installed (check for python linkfinder.py)
        linkfinder_paths = [
            "/opt/LinkFinder/linkfinder.py",
            "linkfinder.py",
            "LinkFinder/linkfinder.py"
        ]
        
        linkfinder_cmd = None
        for path in linkfinder_paths:
            if os.path.exists(path):
                linkfinder_cmd = ["python3", path]
                break
        
        if not linkfinder_cmd:
            # Try to find linkfinder in common locations
            try:
                result = subprocess.run(["find", "/", "-name", "linkfinder.py", "-type", "f", "2>/dev/null"], 
                                      capture_output=True, text=True, timeout=10)
                if result.stdout.strip():
                    linkfinder_path = result.stdout.strip().split('\n')[0]
                    linkfinder_cmd = ["python3", linkfinder_path]
            except:
                pass
        
        if not linkfinder_cmd:
            return {
                "status": "error",
                "error_message": "LinkFinder not found. Please install it with: git clone https://github.com/GerbenJavado/LinkFinder.git"
            }
        
        # Normalize inputs to list
        if isinstance(inputs, str):
            inputs = [inputs]
        
        # Create output directory
        output_dir = "js_link_extraction"
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Categorize inputs
        js_files = []
        urls = []
        
        for input_item in inputs:
            if input_type == "auto":
                # Auto-detect input type
                if input_item.startswith(("http://", "https://")):
                    urls.append(input_item)
                elif input_item.endswith(".js") or os.path.exists(input_item):
                    js_files.append(input_item)
                else:
                    urls.append(input_item)  # Assume URL if not clear
            elif input_type == "js_file":
                js_files.append(input_item)
            elif input_type == "url":
                urls.append(input_item)
            elif input_type == "mixed":
                if input_item.startswith(("http://", "https://")):
                    urls.append(input_item)
                else:
                    js_files.append(input_item)
        
        all_extracted_urls = []
        processing_results = {}
        discovered_js_files = []
        
        # Process URLs - discover JS files using LinkFinder -d flag
        for url in urls:
            try:
                # Discover JS files from URL by crawling
                print(f"Discovering JS files from {url} using LinkFinder...")
                
                # Try to find JS files by crawling the URL
                try:
                    # Use LinkFinder with -d flag to discover JS files
                    discovery_cmd = linkfinder_cmd + ["-i", url, "-d", "-o", "cli"]
                    discovery_result = subprocess.run(discovery_cmd, capture_output=True, text=True, timeout=60)
                    
                    if discovery_result.returncode == 0:
                        # Parse discovered JS files from stdout
                        discovered_from_url = []
                        for line in discovery_result.stdout.split('\n'):
                            line = line.strip()
                            if line and line.endswith('.js'):
                                # Convert relative URLs to absolute if needed
                                if line.startswith('//'):
                                    line = 'https:' + line
                                elif line.startswith('/'):
                                    base_url = '/'.join(url.split('/')[:3])
                                    line = base_url + line
                                elif not line.startswith('http'):
                                    base_url = '/'.join(url.split('/')[:3])
                                    line = base_url + '/' + line
                                discovered_from_url.append(line)
                        
                        discovered_js_files.extend(discovered_from_url)
                        
                        processing_results[url] = {
                            "type": "url_discovery",
                            "js_files_found": len(discovered_from_url),
                            "discovered_files": discovered_from_url
                        }
                    else:
                        processing_results[url] = {
                            "type": "url_discovery", 
                            "error": f"LinkFinder discovery failed: {discovery_result.stderr}"
                        }
                except Exception as discovery_error:
                    processing_results[url] = {
                        "type": "url_discovery",
                        "error": f"Error during JS discovery: {str(discovery_error)}"
                    }
                    continue
                
            except Exception as e:
                processing_results[url] = {
                    "type": "url",
                    "error": str(e)
                }
        
        # Combine discovered JS files with direct JS file inputs
        all_js_files = js_files + list(set(discovered_js_files))
        
        # Process JS files with linkfinder
        for js_file in all_js_files:
            try:
                print(f"Extracting URLs from {js_file}...")
                
                # Create output file for this JS file
                safe_name = re.sub(r'[^\w\-_.]', '_', js_file.split('/')[-1])
                output_file = os.path.join(output_dir, f"{safe_name}_{timestamp}.txt")
                
                # Run linkfinder
                if js_file.startswith(("http://", "https://")):
                    cmd = linkfinder_cmd + ["-i", js_file, "-o", "cli"]
                else:
                    cmd = linkfinder_cmd + ["-i", "https" + js_file, "-o", "cli"]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    # Parse output from stdout
                    extracted_urls = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                    all_extracted_urls.extend(extracted_urls)
                    
                    processing_results[js_file] = {
                        "type": "js_file",
                        "urls_extracted": len(extracted_urls),
                        "stdout_output": len(result.stdout.split("\n"))
                    }
                else:
                    processing_results[js_file] = {
                        "type": "js_file",
                        "error": f"linkfinder failed: {result.stderr}"
                    }
                
            except Exception as e:
                processing_results[js_file] = {
                    "type": "js_file",
                    "error": str(e)
                }
        
        # Save consolidated results
        consolidated_file = os.path.join(output_dir, f"all_extracted_urls_{timestamp}.txt")
        unique_urls = list(set(all_extracted_urls))
        
        with open(consolidated_file, 'w') as f:
            for url in unique_urls:
                f.write(f"{url}\n")
        
        result = {
            "status": "success",
            "timestamp": timestamp,
            "total_inputs": len(inputs),
            "js_files_processed": len(all_js_files),
            "urls_processed": len(urls),
            "js_files_discovered": len(discovered_js_files),
            "total_urls_extracted": len(unique_urls),
            "processing_results": processing_results,
            "extracted_urls": unique_urls,
            "message": f"Processed {len(inputs)} inputs, extracted {len(unique_urls)} unique URLs from {len(all_js_files)} JS files"
        }
        
        # Use first input as target name for file naming
        target_name = inputs[0] if isinstance(inputs, list) else str(inputs)
        return handle_results(result, "get_js_links", target_name, display_results)
        
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"Unexpected error in get_js_links: {str(e)}"
        }

def crawl_target(input_data: str, input_type: str = "auto", display_results: Optional[bool] = None) -> dict:
    """
    Crawl URLs using katana tool with enhanced features including JavaScript parsing.
    
    Features enabled:
    - JavaScript endpoint discovery (-jc)
    - Known files crawling (robots.txt, sitemap.xml)
    - Auto-fill forms for deeper crawling
    - Configurable depth and duration limits
    
    Args:
        input_data: Single URL, list of URLs, or file path containing URLs
        input_type: Type of input - "url", "urls", "file", or "auto" (auto-detect)
        display_results: Whether to display detailed results or just save them
    
    Returns:
        Dictionary containing comprehensive crawling results from katana
    """
    try:
        # Check if katana is installed
        try:
            subprocess.run(["katana", "--version"], capture_output=True, check=True, timeout=10)
        except (subprocess.CalledProcessError, FileNotFoundError):
            return {
                "status": "error",
                "error_message": "katana is not installed or not in PATH. Please install it first."
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "error", 
                "error_message": "katana version check timed out"
            }
        
        # Parse input and determine URLs to crawl
        urls_to_crawl = []
        
        if input_type == "auto":
            # Auto-detect input type
            if isinstance(input_data, str):
                if input_data.startswith(("http://", "https://")):
                    urls_to_crawl = [input_data]
                elif os.path.exists(input_data):
                    # It's a file
                    with open(input_data, "r") as file:
                        urls_to_crawl = [line.strip() for line in file if line.strip()]
                else:
                    # Assume it's a URL without http/https prefix
                    urls_to_crawl = [f"https://{input_data}"]
            elif isinstance(input_data, list):
                urls_to_crawl = input_data
        elif input_type == "url":
            urls_to_crawl = [input_data] if isinstance(input_data, str) else input_data
        elif input_type == "urls":
            urls_to_crawl = input_data if isinstance(input_data, list) else [input_data]
        elif input_type == "file":
            if not os.path.exists(input_data):
                return {
                    "status": "error",
                    "error_message": f"File not found: {input_data}"
                }
            with open(input_data, "r") as file:
                urls_to_crawl = [line.strip() for line in file if line.strip()]
        
        if not urls_to_crawl:
            return {
                "status": "error",
                "error_message": "No URLs found to crawl"
            }
        
        # Create output directory
        output_dir = "katana_crawl_results"
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Process URLs sequentially with katana
        all_crawled_urls = []
        crawl_results = {}
        failed_urls = []
        
        for i, url in enumerate(urls_to_crawl):
            try:
                print(f"Crawling URL {i+1}/{len(urls_to_crawl)}: {url}")
                
                # Ensure URL has protocol
                if not url.startswith(("http://", "https://")):
                    url = f"https://{url}"
                
                # Create individual output file for this URL
                safe_url = re.sub(r'[^\w\-_.]', '_', url.replace("://", "_"))
                individual_output = os.path.join(output_dir, f"{safe_url}_{timestamp}.txt")
                
                # Run katana command for this URL with enhanced options
                cmd = [
                    "katana",
                    "-u", url,
                    "-o", individual_output,
                    "-d", "5",  # Maximum depth to crawl (default 3, increased for better coverage)
                    "-c", "10", # Number of concurrent requests (default 10)
                    "-jc",      # Enable endpoint parsing/crawling in JavaScript files
                    "-hl",      # Enable headless hybrid crawling (correct flag)
                    "-silent",
                    "--no-sandbox"   # Silent output
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)  # 5 minutes per URL
                
                if result.returncode == 0:
                    # Read the crawled URLs from the output file
                    if os.path.exists(individual_output):
                        with open(individual_output, "r") as f:
                            crawled_urls = [line.strip() for line in f if line.strip()]
                    else:
                        crawled_urls = []
                    
                    all_crawled_urls.extend(crawled_urls)
                    crawl_results[url] = {
                        "status": "success",
                        "urls_found": len(crawled_urls),
                        "crawl_depth": 5,
                        "javascript_parsing": True,
                        "known_files_crawled": True,
                        "output_file": individual_output
                    }
                else:
                    failed_urls.append(url)
                    crawl_results[url] = {
                        "status": "failed",
                        "error": result.stderr.strip() if result.stderr else "Unknown error"
                    }
                
            except subprocess.TimeoutExpired:
                failed_urls.append(url)
                crawl_results[url] = {
                    "status": "failed",
                    "error": "Katana command timed out after 5 minutes"
                }
            except Exception as e:
                failed_urls.append(url)
                crawl_results[url] = {
                    "status": "failed",
                    "error": str(e)
                }
        
        # Save consolidated results
        consolidated_file = os.path.join(output_dir, f"all_crawled_urls_{timestamp}.txt")
        unique_urls = list(set(all_crawled_urls))
        
        with open(consolidated_file, "w") as f:
            for url in unique_urls:
                f.write(f"{url}\n")
        
        # Prepare result
        result = {
            "status": "success",
            "timestamp": timestamp,
            "total_input_urls": len(urls_to_crawl),
            "successful_crawls": len(urls_to_crawl) - len(failed_urls),
            "failed_crawls": len(failed_urls),
            "total_urls_discovered": len(unique_urls),
            "crawl_results": crawl_results,
            "discovered_urls": unique_urls,
            "message": f"Crawled {len(urls_to_crawl)} URLs using katana. Found {len(unique_urls)} unique URLs total."
        }
        
        if failed_urls:
            result["failed_urls"] = failed_urls
        
        # Use first input as target name for file naming
        target_name = urls_to_crawl[0] if urls_to_crawl else "unknown"
        return handle_results(result, "crawl_target", target_name, display_results)
        
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"Unexpected error in crawl_target: {str(e)}"
        }

def check_broken_links_blc(input_data: str, input_type: str = "auto", display_results: Optional[bool] = None) -> dict:
    """
    Check for broken links using blc tool with support for multiple input types.
    
    Args:
        input_data: Single URL, list of URLs, or file path containing URLs
        input_type: Type of input - "url", "urls", "file", or "auto" (auto-detect)
    
    Returns:
        Dictionary containing broken link check results from blc
    """
    try:
        # Check if blc is installed
        try:
            subprocess.run(["blc", "--help"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            return {
                "status": "error",
                "error_message": "broken-link-checker (blc) is not installed or not in PATH. Please install it with 'npm install -g broken-link-checker'."
            }
        
        # Parse input and determine URLs to check
        urls_to_check = []
        
        if input_type == "auto":
            # Auto-detect input type
            if isinstance(input_data, str):
                if input_data.startswith(("http://", "https://")):
                    urls_to_check = [input_data]
                elif os.path.exists(input_data):
                    # It's a file
                    with open(input_data, "r") as file:
                        urls_to_check = [line.strip() for line in file if line.strip()]
                else:
                    # Assume it's a URL without http/https prefix
                    urls_to_check = [f"https://{input_data}"]
            elif isinstance(input_data, list):
                urls_to_check = input_data
        elif input_type == "url":
            urls_to_check = [input_data] if isinstance(input_data, str) else input_data
        elif input_type == "urls":
            urls_to_check = input_data if isinstance(input_data, list) else [input_data]
        elif input_type == "file":
            if not os.path.exists(input_data):
                return {
                    "status": "error",
                    "error_message": f"File not found: {input_data}"
                }
            with open(input_data, "r") as file:
                urls_to_check = [line.strip() for line in file if line.strip()]
        
        if not urls_to_check:
            return {
                "status": "error",
                "error_message": "No URLs found to check"
            }
        
        # Create output directory
        output_dir = "blc_broken_links"
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Process URLs sequentially with blc
        all_broken_links = []
        check_results = {}
        failed_urls = []
        
        for i, url in enumerate(urls_to_check):
            try:
                print(f"Checking URL {i+1}/{len(urls_to_check)}: {url}")
                
                # Ensure URL has protocol
                if not url.startswith(("http://", "https://")):
                    url = f"https://{url}"
                
                # Create individual output file for this URL
                safe_url = re.sub(r'[^\w\-_.]', '_', url.replace("://", "_"))
                individual_output = os.path.join(output_dir, f"{safe_url}_{timestamp}.json")
                
                # Run blc command for this URL
                cmd = [
                    "blc",
                    url,
                    "-ro"
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)  # 10 minutes per URL
                
                # Parse the output
                broken_links = []
                
                if result.returncode == 0:
                    if result.stdout:
                        # Parse BLC output (it outputs plain text, not JSON)
                        # BLC shows broken links with status codes and error messages
                        lines = result.stdout.splitlines()
                        
                        for line in lines:
                            # Look for patterns indicating broken links
                            if any(pattern in line.upper() for pattern in ["BROKEN", "404", "ERROR", "TIMEOUT", "FAILED"]):
                                # Extract URL from line using regex
                                url_match = re.search(r'https?://[^\s]+', line)
                                if url_match:
                                    broken_url = url_match.group(0)
                                    # Extract status code if present
                                    status_match = re.search(r'\b(\d{3})\b', line)
                                    status_code = status_match.group(1) if status_match else "unknown"
                                    
                                    broken_links.append({
                                        "url": broken_url,
                                        "status_code": status_code,
                                        "status_text": line.strip(),
                                        "parent_url": url,
                                        "text": "",
                                        "source": "blc"
                                    })
                    
                    # Save results to file
                    with open(individual_output, "w") as f:
                        json.dump(broken_links, f, indent=2)
                    
                    all_broken_links.extend(broken_links)
                    check_results[url] = {
                        "status": "success",
                        "broken_links_found": len(broken_links),
                        "output_file": individual_output
                    }
                    
                else:
                    failed_urls.append(url)
                    check_results[url] = {
                        "status": "failed",
                        "error": result.stderr.strip() if result.stderr else "Unknown error"
                    }
                
            except subprocess.TimeoutExpired:
                failed_urls.append(url)
                check_results[url] = {
                    "status": "failed",
                    "error": "BLC command timed out after 10 minutes"
                }
            except Exception as e:
                failed_urls.append(url)
                check_results[url] = {
                    "status": "failed",
                    "error": str(e)
                }
        
        # Save consolidated results
        consolidated_file = os.path.join(output_dir, f"all_broken_links_{timestamp}.json")
        unique_broken_links = []
        seen_urls = set()
        
        for link in all_broken_links:
            if link["url"] not in seen_urls:
                unique_broken_links.append(link)
                seen_urls.add(link["url"])
        
        with open(consolidated_file, "w") as f:
            json.dump(unique_broken_links, f, indent=2)
        
        # Prepare result
        result = {
            "status": "success",
            "timestamp": timestamp,
            "total_input_urls": len(urls_to_check),
            "successful_checks": len(urls_to_check) - len(failed_urls),
            "failed_checks": len(failed_urls),
            "total_broken_links": len(unique_broken_links),
            "check_results": check_results,
            "broken_links": unique_broken_links,
            "message": f"Checked {len(urls_to_check)} URLs using blc. Found {len(unique_broken_links)} unique broken links total."
        }
        
        if failed_urls:
            result["failed_urls"] = failed_urls
        
        # Use first input as target name for file naming
        target_name = urls_to_check[0] if urls_to_check else "unknown"
        return handle_results(result, "check_broken_links_blc", target_name, display_results)
        
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"Unexpected error in check_broken_links_blc: {str(e)}"
        }

def social_media_recon(input_data: str, input_type: str = "auto", display_results: Optional[bool] = None) -> dict:
    """
    Perform social media reconnaissance using socialhunter tool with support for multiple input types.
    
    Args:
        input_data: Single URL, list of URLs, or file path containing URLs
        input_type: Type of input - "url", "urls", "file", or "auto" (auto-detect)
    
    Returns:
        Dictionary containing social media reconnaissance results from socialhunter
    """
    try:
        # Check if socialhunter is installed
        try:
            subprocess.run(["socialhunter", "-h"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            return {
                "status": "error",
                "error_message": "socialhunter is not installed or not in PATH. Please install it first."
            }
        
        # Parse input and determine URLs to check
        urls_to_check = []
        
        if input_type == "auto":
            # Auto-detect input type
            if isinstance(input_data, str):
                if input_data.startswith(("http://", "https://")):
                    urls_to_check = [input_data]
                elif os.path.exists(input_data):
                    # It's a file
                    with open(input_data, "r") as file:
                        urls_to_check = [line.strip() for line in file if line.strip()]
                else:
                    # Assume it's a URL without http/https prefix
                    urls_to_check = [f"https://{input_data}"]
            elif isinstance(input_data, list):
                urls_to_check = input_data
        elif input_type == "url":
            urls_to_check = [input_data] if isinstance(input_data, str) else input_data
        elif input_type == "urls":
            urls_to_check = input_data if isinstance(input_data, list) else [input_data]
        elif input_type == "file":
            if not os.path.exists(input_data):
                return {
                    "status": "error",
                    "error_message": f"File not found: {input_data}"
                }
            with open(input_data, "r") as file:
                urls_to_check = [line.strip() for line in file if line.strip()]
        
        if not urls_to_check:
            return {
                "status": "error",
                "error_message": "No URLs found to check"
            }
        
        # Create output directory
        output_dir = "socialhunter_results"
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Process URLs with socialhunter
        all_social_links = []
        all_broken_links = []
        recon_results = {}
        failed_urls = []
        
        for i, url in enumerate(urls_to_check):
            try:
                print(f"Running socialhunter on URL {i+1}/{len(urls_to_check)}: {url}")
                
                # Ensure URL has protocol
                if not url.startswith(("http://", "https://")):
                    url = f"https://{url}"
                
                # Create individual input file for this URL (socialhunter requires file input)
                safe_url = re.sub(r'[^\w\-_.]', '_', url.replace("://", "_"))
                individual_input = os.path.join(output_dir, f"{safe_url}_{timestamp}_input.txt")
                
                # Write URL to input file (socialhunter requires -f flag with file input)
                with open(individual_input, "w") as f:
                    f.write(f"{url}\n")
                
                # Run socialhunter command for this URL
                cmd = [
                    "socialhunter",
                    "-f", individual_input,  # File input (required)
                    "-w", "5"  # Number of workers
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)  # 10 minutes per URL
                
                # Parse the output from stdout
                social_links = []
                broken_links = []
                
                if result.returncode == 0 and result.stdout:
                    try:
                        # Parse stdout output from socialhunter
                        data = json.loads(result.stdout)
                        
                        # Extract social media links and broken links based on socialhunter's JSON format
                        if isinstance(data, list):
                            for item in data:
                                    if isinstance(item, dict):
                                        # Extract social media links
                                        social_media_links = item.get("socialMediaLinks", [])
                                        for link in social_media_links:
                                            social_links.append({
                                                "url": link.get("url", ""),
                                                "platform": link.get("platform", "unknown"),
                                                "status": link.get("status", "unknown"),
                                                "parent_url": item.get("url", url),
                                                "source": "socialhunter"
                                            })
                                        
                                        # Extract broken links
                                        broken_social_links = item.get("brokenLinks", [])
                                        for link in broken_social_links:
                                            broken_links.append({
                                                "url": link.get("url", ""),
                                                "platform": link.get("platform", "unknown"),
                                                "status_code": link.get("statusCode", "unknown"),
                                                "parent_url": item.get("url", url),
                                                "source": "socialhunter"
                                            })
                        elif isinstance(data, dict):
                            # Extract social media links
                            social_media_links = data.get("socialMediaLinks", [])
                            for link in social_media_links:
                                social_links.append({
                                    "url": link.get("url", ""),
                                    "platform": link.get("platform", "unknown"),
                                    "status": link.get("status", "unknown"),
                                    "parent_url": data.get("url", url),
                                    "source": "socialhunter"
                                })
                            
                            # Extract broken links
                            broken_social_links = data.get("brokenLinks", [])
                            for link in broken_social_links:
                                broken_links.append({
                                    "url": link.get("url", ""),
                                    "platform": link.get("platform", "unknown"),
                                    "status_code": link.get("statusCode", "unknown"),
                                    "parent_url": data.get("url", url),
                                    "source": "socialhunter"
                                })
                    except json.JSONDecodeError:
                        # If JSON parsing fails, parse stdout as text
                        content = result.stdout
                        # Basic text parsing for social media links
                        lines = content.splitlines()
                        for line in lines:
                            if any(platform in line.lower() for platform in ["twitter", "facebook", "instagram", "linkedin", "youtube", "github"]):
                                social_links.append({
                                    "url": line.strip(),
                                    "platform": "unknown",
                                    "status": "unknown", 
                                    "parent_url": url,
                                    "source": "socialhunter"
                                })
                    
                    # Save results to JSON file
                    individual_output = os.path.join(output_dir, f"{safe_url}_{timestamp}_results.json")
                    results_data = {
                        "url": url,
                        "social_links": social_links,
                        "broken_links": broken_links,
                        "timestamp": timestamp
                    }
                    with open(individual_output, "w") as f:
                        json.dump(results_data, f, indent=2)
                    
                    all_social_links.extend(social_links)
                    all_broken_links.extend(broken_links)
                    recon_results[url] = {
                        "status": "success",
                        "social_links_found": len(social_links),
                        "broken_links_found": len(broken_links),
                        "output_file": individual_output
                    }
                    
                else:
                    failed_urls.append(url)
                    recon_results[url] = {
                        "status": "failed",
                        "error": result.stderr.strip() if result.stderr else "Unknown error"
                    }
                
            except subprocess.TimeoutExpired:
                failed_urls.append(url)
                recon_results[url] = {
                    "status": "failed",
                    "error": "Socialhunter command timed out after 10 minutes"
                }
            except Exception as e:
                failed_urls.append(url)
                recon_results[url] = {
                    "status": "failed",
                    "error": str(e)
                }
        
        # Save consolidated results
        consolidated_social_file = os.path.join(output_dir, f"all_social_links_{timestamp}.json")
        consolidated_broken_file = os.path.join(output_dir, f"all_broken_social_links_{timestamp}.json")
        
        # Remove duplicates
        unique_social_links = []
        unique_broken_links = []
        seen_social_urls = set()
        seen_broken_urls = set()
        
        for link in all_social_links:
            if link["url"] not in seen_social_urls:
                unique_social_links.append(link)
                seen_social_urls.add(link["url"])
        
        for link in all_broken_links:
            if link["url"] not in seen_broken_urls:
                unique_broken_links.append(link)
                seen_broken_urls.add(link["url"])
        
        with open(consolidated_social_file, "w") as f:
            json.dump(unique_social_links, f, indent=2)
        
        with open(consolidated_broken_file, "w") as f:
            json.dump(unique_broken_links, f, indent=2)
        
        # Prepare result
        result = {
            "status": "success",
            "timestamp": timestamp,
            "total_input_urls": len(urls_to_check),
            "successful_scans": len(urls_to_check) - len(failed_urls),
            "failed_scans": len(failed_urls),
            "total_social_links": len(unique_social_links),
            "total_broken_links": len(unique_broken_links),
            "recon_results": recon_results,
            "social_links": unique_social_links,
            "broken_links": unique_broken_links,
            "message": f"Scanned {len(urls_to_check)} URLs using socialhunter. Found {len(unique_social_links)} social media links and {len(unique_broken_links)} broken links."
        }
        
        if failed_urls:
            result["failed_urls"] = failed_urls
        
        # Use first input as target name for file naming
        target_name = urls_to_check[0] if urls_to_check else "unknown"
        return handle_results(result, "social_media_recon", target_name, display_results)
        
    except Exception as e:
        return {
            "status": "error",
            "error_message": f"Unexpected error in social_media_recon: {str(e)}"
        }

def check_broken_links(target: str, tools: str = "all") -> dict:
    """
    Check for broken links on a target domain or URL using various tools.
    
    Args:
        target: The target domain, URL, or file path containing targets (one per line)
        tools: Comma-separated list of tools to use (blc,socialhunter) or "all"
    
    Returns:
        Dictionary containing discovered broken links
    """
    try:
        # Determine if target is a file path
        targets_list = []
        is_file_target = False
        if os.path.exists(target) and os.path.isfile(target):
            is_file_target = True
            with open(target, "r") as file:
                targets_list = [line.strip() for line in file if line.strip()]
            
            if not targets_list:
                return {
                    "status": "error",
                    "target": target,
                    "error_message": f"No valid targets found in file: {target}"
                }
        else:
            # Single target
            targets_list = [target]
        
        # Determine which tools to run
        available_tools = ["blc", "socialhunter"]
        selected_tools = []
        
        if tools.lower() == "all":
            selected_tools = available_tools
        else:
            selected_tools = [t.strip().lower() for t in tools.split(",") if t.strip()]
            # Validate tool names
            for tool in selected_tools:
                if tool not in available_tools:
                    return {
                        "status": "error",
                        "target": target,
                        "error_message": f"Invalid tool specified: {tool}. Available tools: {', '.join(available_tools)}"
                    }
        
        # Create output directory
        output_dir = "broken_links_results"
        os.makedirs(output_dir, exist_ok=True)
        
        # Run each tool and collect broken links
        all_broken_links = []
        tool_results = {}
        
        for tool in selected_tools:
            try:
                print(f"Running {tool} on {target}...")
                
                # Prepare input data for individual tool functions
                if is_file_target:
                    input_data = targets_list
                    input_type = "urls"
                else:
                    input_data = targets_list[0] if len(targets_list) == 1 else targets_list
                    input_type = "url" if len(targets_list) == 1 else "urls"
                
                # Run the appropriate tool
                if tool == "blc":
                    result = check_broken_links_blc(input_data, input_type)
                elif tool == "socialhunter":
                    result = social_media_recon(input_data, input_type)
                
                # Add to results
                if result["status"] == "success":
                    if tool == "blc":
                        all_broken_links.extend(result.get("broken_links", []))
                        tool_results[tool] = {
                            "total_broken_links": len(result.get("broken_links", [])),
                            "output_file": result.get("consolidated_file", "")
                        }
                    elif tool == "socialhunter":
                        # For socialhunter, we want both social links and broken links
                        all_broken_links.extend(result.get("broken_links", []))
                        tool_results[tool] = {
                            "total_social_links": len(result.get("social_links", [])),
                            "total_broken_links": len(result.get("broken_links", [])),
                            "social_output_file": result.get("consolidated_social_file", ""),
                            "broken_output_file": result.get("consolidated_broken_file", "")
                        }
                else:
                    tool_results[tool] = {
                        "error": result.get("error_message", "Unknown error")
                    }
                
            except Exception as e:
                print(f"Error running {tool}: {e}")
                tool_results[tool] = {
                    "error": f"Error running {tool}: {str(e)}"
                }
        
        # Remove duplicate broken links
        unique_broken_links = []
        seen_links = set()
        
        for link in all_broken_links:
            link_url = link.get("url", "")
            if link_url and link_url not in seen_links:
                seen_links.add(link_url)
                unique_broken_links.append(link)
        
        # Save consolidated results to main file
        output_file = os.path.join(output_dir, "all_broken_links.json")
        with open(output_file, "w") as outfile:
            json.dump(unique_broken_links, outfile, indent=2)
        
        # Group broken links by status code
        status_codes = {}
        for link in unique_broken_links:
            status = link.get("status_code", "unknown")
            if status not in status_codes:
                status_codes[status] = 0
            status_codes[status] += 1
        
        if unique_broken_links:
            return {
                "status": "success",
                "target": target,
                "timestamp": datetime.datetime.now().isoformat(),
                "broken_links": unique_broken_links[:100],  # Limit to 100 links in the response
                "total_broken_links": len(unique_broken_links),
                "status_codes": status_codes,
                "tool_results": tool_results,
                "stdout_output": len(result.stdout.split("\n")),
                "message": f"Found {len(unique_broken_links)} unique broken links using {len(selected_tools)} tools. Results saved to {output_file}"
            }
        else:
            return {
                "status": "success",
                "target": target,
                "tool_results": tool_results,
                "message": f"No broken links found for {target} using the selected tools."
            }
        
    except Exception as e:
        return {
            "status": "error",
            "target": target,
            "error_message": f"Unexpected error during broken link checking: {str(e)}"
        }

def api_recon(search_term: str, display_results: Optional[bool] = None) -> dict:
    """
    Perform API reconnaissance using SwaggerHub and Postman API searches.
    
    Args:
        search_term: The search term to look for in API documentation and collections
        display_results: True to show all, False to hide, None to auto-manage if >50 lines
    
    Returns:
        Dictionary containing discovered API documentation and collections
    """
    try:
        # Generate timestamp for file naming
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create output directory
        output_dir = "api_recon_results"
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize results
        swagger_results = []
        postman_results = []
        errors = []
        
        # Search SwaggerHub API
        try:
            print(f"Searching SwaggerHub for: {search_term}")
            swagger_results = _search_swaggerhub(search_term)
            
            # Save SwaggerHub results
            safe_search_term = re.sub(r'[^\\w\\-_.]', '_', search_term)
            swagger_filename = f"{output_dir}/api_recon_swagger_{safe_search_term}_{timestamp}.txt"
            with open(swagger_filename, 'w') as f:
                f.write(f"SwaggerHub API Search Results for: {search_term}\\n")
                f.write(f"Search Date: {datetime.datetime.now().isoformat()}\\n")
                f.write("=" * 50 + "\\n\\n")
                
                if swagger_results:
                    for i, result in enumerate(swagger_results, 1):
                        f.write(f"{i}. {result.get('name', 'Unknown API')}\\n")
                        f.write(f"   URL: {result.get('url', 'N/A')}\\n")
                        f.write(f"   Description: {result.get('description', 'N/A')}\\n")
                        f.write(f"   Version: {result.get('version', 'N/A')}\\n")
                        f.write(f"   Owner: {result.get('owner', 'N/A')}\\n")
                        f.write("-" * 40 + "\\n")
                else:
                    f.write("No SwaggerHub results found.\\n")
                    
        except Exception as e:
            errors.append(f"SwaggerHub search error: {str(e)}")
            swagger_results = []
            
        # Search Postman API
        try:
            print(f"Searching Postman for: {search_term}")
            postman_results = _search_postman(search_term)
            
            # Save Postman results
            postman_filename = f"{output_dir}/api_recon_postman_{safe_search_term}_{timestamp}.txt"
            with open(postman_filename, 'w') as f:
                f.write(f"Postman API Search Results for: {search_term}\\n")
                f.write(f"Search Date: {datetime.datetime.now().isoformat()}\\n")
                f.write("=" * 50 + "\\n\\n")
                
                if postman_results:
                    for i, result in enumerate(postman_results, 1):
                        f.write(f"{i}. {result.get('name', 'Unknown Collection')}\\n")
                        f.write(f"   URL: {result.get('url', 'N/A')}\\n")
                        f.write(f"   Description: {result.get('description', 'N/A')}\\n")
                        f.write(f"   Created: {result.get('created', 'N/A')}\\n")
                        f.write(f"   Updated: {result.get('updated', 'N/A')}\\n")
                        f.write("-" * 40 + "\\n")
                else:
                    f.write("No Postman results found.\\n")
                    
        except Exception as e:
            errors.append(f"Postman search error: {str(e)}")
            postman_results = []
        
        # Combine results
        all_results = swagger_results + postman_results
        
        # Prepare result dictionary
        result = {
            "status": "success",
            "search_term": search_term,
            "timestamp": timestamp,
            "swagger_results": swagger_results,
            "postman_results": postman_results,
            "total_swagger_results": len(swagger_results),
            "total_postman_results": len(postman_results),
            "total_results": len(all_results),
            "results": all_results,
            "message": f"Found {len(swagger_results)} SwaggerHub APIs and {len(postman_results)} Postman collections for '{search_term}'"
        }
        
        if errors:
            result["errors"] = errors
        
        return handle_results(result, "api_recon", search_term, display_results)
        
    except Exception as e:
        return {
            "status": "error",
            "search_term": search_term,
            "error_message": f"Unexpected error in api_recon: {str(e)}"
        }

def _search_swaggerhub(search_term: str) -> list:
    """
    Search SwaggerHub API for API documentation.
    
    Args:
        search_term: The search term to look for
    
    Returns:
        List of API documentation results
    """
    try:
        # SwaggerHub Registry API search endpoint
        url = "https://api.swaggerhub.com/apis"
        
        # Search parameters for Registry API
        params = {
            "query": search_term,
            "limit": 100,
            "sort": "NAME", 
            "state": "ALL"  # Include all API states (published/unpublished)
        }
        
        # Add headers for better API compatibility
        headers = {
            "Accept": "application/json",
            "User-Agent": "API-Recon-Tool/1.0"
        }
        
        # Make request
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        results = []
        
        # Process results
        if "apis" in data:
            for api in data["apis"]:
                api_info = {
                    "name": api.get("name", ""),
                    "url": f"https://app.swaggerhub.com/apis/{api.get('owner', '')}/{api.get('name', '')}",
                    "description": api.get("description", ""),
                    "version": api.get("version", ""),
                    "owner": api.get("owner", ""),
                    "created": api.get("created", ""),
                    "modified": api.get("modified", ""),
                    "source": "swaggerhub"
                }
                results.append(api_info)
        
        return results
        
    except requests.exceptions.RequestException as e:
        print(f"SwaggerHub API request failed: {e}")
        return []
    except Exception as e:
        print(f"SwaggerHub search error: {e}")
        return []

def _search_postman(search_term: str) -> list:
    """
    Search Postman API for collections.
    
    Args:
        search_term: The search term to look for
    
    Returns:
        List of Postman collection results
    """
    try:
        # Note: Postman API Network requires authentication for programmatic access
        # Using web scraping as the primary method for public collection discovery
        # since the official API requires API keys for collection search
        
        # Try the official Postman API first (may require authentication)
        try:
            # Official Postman API endpoint (requires API key)
            api_url = "https://api.getpostman.com/search"
            api_params = {
                "q": search_term,
                "type": "collection",
                "limit": 100
            }
            api_headers = {
                "User-Agent": "API-Recon-Tool/1.0",
                "Accept": "application/json"
            }
            
            # Attempt API call (will likely fail without API key)
            response = requests.get(api_url, params=api_params, headers=api_headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                results = []
                
                # Process API response if successful
                if "data" in data:
                    for item in data["data"]:
                        if item.get("type") == "collection":
                            collection_info = {
                                "name": item.get("name", ""),
                                "url": item.get("url", ""),
                                "description": item.get("description", ""),
                                "created": item.get("createdAt", ""),
                                "updated": item.get("updatedAt", ""),
                                "author": item.get("owner", {}).get("username", ""),
                                "source": "postman"
                            }
                            results.append(collection_info)
                
                return results
                
        except Exception:
            pass  # Fall back to web scraping
        
        # Primary method: web scraping (more reliable for public collections)
        return _scrape_postman_collections(search_term)
        
    except requests.exceptions.RequestException as e:
        print(f"Postman API request failed: {e}")
        return _scrape_postman_collections(search_term)
    except Exception as e:
        print(f"Postman search error: {e}")
        return _scrape_postman_collections(search_term)

def _scrape_postman_collections(search_term: str) -> list:
    """
    Scrape Postman website for public collections as fallback.
    
    Args:
        search_term: The search term to look for
    
    Returns:
        List of Postman collection results
    """
    try:
        # Postman search URL
        search_url = f"https://www.postman.com/search?q={search_term}&type=collection"
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        
        response = requests.get(search_url, headers=headers, timeout=30)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        results = []
        
        # Look for collection cards/items
        collection_items = soup.find_all(['div', 'article'], class_=re.compile(r'collection|search-result'))
        
        for item in collection_items:
            try:
                # Extract collection information
                name_elem = item.find(['h3', 'h4', 'a'], class_=re.compile(r'title|name'))
                desc_elem = item.find(['p', 'div'], class_=re.compile(r'description'))
                link_elem = item.find('a', href=True)
                
                if name_elem and link_elem:
                    collection_info = {
                        "name": name_elem.get_text(strip=True),
                        "url": link_elem['href'] if link_elem['href'].startswith('http') else f"https://www.postman.com{link_elem['href']}",
                        "description": desc_elem.get_text(strip=True) if desc_elem else "",
                        "created": "",
                        "updated": "",
                        "author": "",
                        "source": "postman_scraped"
                    }
                    results.append(collection_info)
                    
            except Exception as e:
                continue
        
        return results[:50]  # Limit to 50 results
        
    except Exception as e:
        print(f"Postman scraping error: {e}")
        return []

def scan_parameters(file_path: str, tools: str = "all") -> dict:
    """
    Scan for URL parameters from a file of subdomains or URLs using various tools.
    
    Args:
        file_path: Path to the file containing subdomains or URLs (one per line)
        tools: Comma-separated list of tools to use (fallparams,unfurl) or "all"
    
    Returns:
        Dictionary containing discovered parameters and analysis
    """
    try:
        if not os.path.exists(file_path):
            return {
                "status": "error",
                "file_path": file_path,
                "error_message": f"File not found: {file_path}. Please ensure the file exists and contains URLs or subdomains (one per line).",
                "suggestion": "Create a file with URLs or subdomains to scan for parameters, one per line (e.g., https://example.com/page?param=value, subdomain.example.com)."
            }
        
        # Read targets from file
        with open(file_path, "r") as file:
            targets = [line.strip() for line in file if line.strip()]
        
        if not targets:
            return {
                "status": "error",
                "file_path": file_path,
                "error_message": f"No targets found in file: {file_path}. The file exists but appears to be empty or contains no valid URLs/subdomains.",
                "suggestion": "Ensure the file contains valid URLs or subdomains, one per line (e.g., https://example.com/page, subdomain.example.com)."
            }
        
        # Determine which tools to run
        available_tools = ["fallparams", "unfurl"]
        selected_tools = []
        
        if tools.lower() == "all":
            selected_tools = available_tools
        else:
            selected_tools = [t.strip().lower() for t in tools.split(",") if t.strip()]
            # Validate tool names
            for tool in selected_tools:
                if tool not in available_tools:
                    return {
                        "status": "error",
                        "file_path": file_path,
                        "error_message": f"Invalid tool specified: {tool}. Available tools: {', '.join(available_tools)}"
                    }
        
        # Create output directory
        output_dir = "parameter_scan_results"
        os.makedirs(output_dir, exist_ok=True)
        
        # Run each tool and collect parameters
        all_params = []
        tool_results = {}
        
        # Prepare URLs file - some tools need full URLs
        urls_file = os.path.join(output_dir, "urls_for_param_scan.txt")
        with open(urls_file, "w") as outfile:
            for target in targets:
                # Check if the target is already a URL, if not make it one
                if not target.startswith("http://") and not target.startswith("https://"):
                    outfile.write(f"https://{target}\n")
                    outfile.write(f"http://{target}\n")
                else:
                    outfile.write(f"{target}\n")
        
        for tool in selected_tools:
            try:
                print(f"Running {tool} on {file_path}...")
                
                # Run the appropriate tool
                if tool == "fallparams":
                    result = _run_fallparams(urls_file, output_dir)
                elif tool == "unfurl":
                    result = _run_unfurl(urls_file, output_dir)
                
                # Add to results
                if result["status"] == "success":
                    all_params.extend(result.get("parameters", []))
                    tool_results[tool] = {
                        "total_params": len(result.get("parameters", [])),
                        "output_file": result.get("output_file", "")
                    }
                else:
                    tool_results[tool] = {
                        "error": result.get("error_message", "Unknown error")
                    }
                
            except Exception as e:
                print(f"Error running {tool}: {e}")
                tool_results[tool] = {
                    "error": f"Error running {tool}: {str(e)}"
                }
        
        # Remove duplicate parameters (if they have the same name and url)
        unique_params = []
        seen_params = set()
        
        for param in all_params:
            param_key = f"{param.get('url', '')}|{param.get('name', '')}"
            if param_key not in seen_params:
                seen_params.add(param_key)
                unique_params.append(param)
        
        # Save consolidated results to main file
        output_file = os.path.join(output_dir, f"all_parameters.json")
        with open(output_file, "w") as outfile:
            json.dump(unique_params, outfile, indent=2)
        
        # Group parameters by potential vulnerability type (basic categorization)
        param_categories = {
            "xss": [],
            "sqli": [],
            "path_traversal": [],
            "open_redirect": [],
            "other": []
        }
        
        xss_keywords = ["q", "s", "search", "query", "keyword", "data", "input", "html", "text", "content"]
        sqli_keywords = ["id", "uid", "user", "item", "product", "category", "page_id", "post"]
        path_keywords = ["path", "file", "dir", "folder", "load", "download", "upload", "include"]
        redirect_keywords = ["url", "link", "redirect", "return", "next", "goto", "target", "destination"]
        
        for param in unique_params:
            name = param.get("name", "").lower()
            if any(keyword in name for keyword in xss_keywords):
                param_categories["xss"].append(param)
            elif any(keyword in name for keyword in sqli_keywords):
                param_categories["sqli"].append(param)
            elif any(keyword in name for keyword in path_keywords):
                param_categories["path_traversal"].append(param)
            elif any(keyword in name for keyword in redirect_keywords):
                param_categories["open_redirect"].append(param)
            else:
                param_categories["other"].append(param)
        
        if unique_params:
            return {
                "status": "success",
                "file_path": file_path,
                "timestamp": datetime.datetime.now().isoformat(),
                "parameters": unique_params[:100],  # Limit to 100 parameters in the response
                "total_parameters": len(unique_params),
                "parameter_categories": {
                    "xss_candidates": len(param_categories["xss"]),
                    "sqli_candidates": len(param_categories["sqli"]),
                    "path_traversal_candidates": len(param_categories["path_traversal"]),
                    "open_redirect_candidates": len(param_categories["open_redirect"]),
                    "other": len(param_categories["other"])
                },
                "tool_results": tool_results,
                "stdout_output": len(result.stdout.split("\n")),
                "message": f"Found {len(unique_params)} unique parameters using {len(selected_tools)} tools. Results saved to {output_file}"
            }
        else:
            return {
                "status": "error",
                "file_path": file_path,
                "tool_results": tool_results,
                "error_message": f"No parameters found for targets in {file_path} using the selected tools."
            }
            
    except Exception as e:
        return {
            "status": "error",
            "file_path": file_path,
            "error_message": f"Unexpected error during parameter scanning: {str(e)}"
        }

def _run_fallparams(file_path: str, output_dir: str) -> dict:
    """
    Run fallparams to discover parameters from URLs.
    """
    # Define output file path
    output_file = os.path.join(output_dir, "fallparams_results.txt")
    
    # Check if fallparams is installed
    try:
        subprocess.run(["fallparams", "-h"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("fallparams is not installed or not in PATH")
        return {
            "status": "error",
            "file_path": file_path,
            "error_message": "fallparams is not installed or not in PATH. Please install it first."
        }
    
    # Run fallparams command with correct flags
    cmd = [
        "fallparams", 
        "-u", file_path,  # Input URL or filename with URLs (correct flag)
        "-o", output_file,  # Output file
        "-c",  # Enable crawling to extract parameters
        "-d", "3",  # Set crawl depth to 3 for better coverage
        "-hl"  # Enable headless browser for dynamic content discovery
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)  # 15 minutes timeout for headless mode
        
        if result.returncode != 0:
            print(f"fallparams command failed: {result.stderr}")
            return {
                "status": "error",
                "file_path": file_path,
                "error_message": f"fallparams command failed: {result.stderr}"
            }
        
        # Process the results
        parameters = []
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, "r", encoding="utf-8") as file:
                for line in file:
                    line = line.strip()
                    if line and not line.startswith("#"):  # Skip comments
                        # Enhanced parsing for different fallparams output formats
                        
                        # Format 1: URL [parameter=value]
                        if "[" in line and "]" in line:
                            url_parts = line.split(" ", 1)
                            url = url_parts[0] if len(url_parts) > 0 else ""
                            
                            # Extract parameter if present
                            if len(url_parts) > 1 and "[" in url_parts[1] and "]" in url_parts[1]:
                                param_part = url_parts[1].strip("[]")
                                if "=" in param_part:
                                    param_name, param_value = param_part.split("=", 1)
                                    parameters.append({
                                        "url": url,
                                        "name": param_name,
                                        "value": param_value,
                                        "source": "fallparams"
                                    })
                        
                        # Format 2: Simple parameter names (wordlist format)
                        elif line and not line.startswith("http") and "=" not in line:
                            # Single parameter name on each line
                            parameters.append({
                                "url": "",
                                "name": line,
                                "value": "",
                                "source": "fallparams"
                            })
                        
                        # Format 3: URL with query parameters
                        elif "?" in line and "=" in line:
                            # Extract parameters from URL query string
                            import urllib.parse
                            parsed_url = urllib.parse.urlparse(line)
                            query_params = urllib.parse.parse_qs(parsed_url.query)
                            
                            for param_name, param_values in query_params.items():
                                parameters.append({
                                    "url": line,
                                    "name": param_name,
                                    "value": param_values[0] if param_values else "",
                                    "source": "fallparams"
                                })
        
        return {
            "status": "success",
            "file_path": file_path,
            "parameters": parameters,
            "stdout_output": len(result.stdout.split("\n")),
            "message": f"Found {len(parameters)} parameters with fallparams. Results saved to {output_file}"
        }
    
    except subprocess.TimeoutExpired:
        print("fallparams command timed out after 15 minutes")
        return {
            "status": "error",
            "file_path": file_path,
            "error_message": "fallparams command timed out after 15 minutes"
        }
    except Exception as e:
        print(f"Unexpected error running fallparams: {str(e)}")
        return {
            "status": "error",
            "file_path": file_path,
            "error_message": f"Unexpected error running fallparams: {str(e)}"
        }


def _run_unfurl(file_path: str, output_dir: str) -> dict:
    """
    Run unfurl to analyze URL structures and parameters.
    """
    # Define output file path
    output_file = os.path.join(output_dir, "unfurl_results.json")
    
    # Check if unfurl is installed
    try:
        subprocess.run(["unfurl", "-h"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("unfurl is not installed or not in PATH")
        return {
            "status": "error",
            "file_path": file_path,
            "error_message": "unfurl is not installed or not in PATH. Please install it first."
        }
    
    # Process URLs with unfurl (correct syntax)
    parameters = []
    
    try:
        with open(file_path, "r") as file:
            urls = [line.strip() for line in file if line.strip()]
        
        if not urls:
            return {
                "status": "error",
                "file_path": file_path,
                "error_message": "No URLs found in the input file"
            }
        
        # Use unfurl to extract query parameters
        # Method 1: Extract query key-value pairs
        urls_input = '\n'.join(urls)
        cmd = ["unfurl", "keypairs"]
        result = subprocess.run(cmd, input=urls_input, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            keypairs = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            
            # Process keypairs to extract parameters
            for keypair in keypairs:
                if "=" in keypair:
                    param_name, param_value = keypair.split("=", 1)
                    # Find which URL this parameter came from by checking each URL
                    for url in urls:
                        if keypair in url:
                            parameters.append({
                                "url": url,
                                "name": param_name,
                                "value": param_value,
                                "source": "unfurl"
                            })
                            break
        
        # Method 2: Also extract just parameter keys for comprehensive coverage
        cmd_keys = ["unfurl", "--unique", "keys"]
        result_keys = subprocess.run(cmd_keys, input=urls_input, capture_output=True, text=True, timeout=300)
        
        if result_keys.returncode == 0:
            keys = [line.strip() for line in result_keys.stdout.splitlines() if line.strip()]
            
            # Add keys that weren't captured in keypairs
            existing_params = {p["name"] for p in parameters}
            for key in keys:
                if key not in existing_params:
                    # Find which URL this key came from
                    for url in urls:
                        if key in url:
                            parameters.append({
                                "url": url,
                                "name": key,
                                "value": "",
                                "source": "unfurl"
                            })
                            break
        
        # Method 3: Extract domains and paths for additional context
        domains_cmd = ["unfurl", "--unique", "domains"]
        paths_cmd = ["unfurl", "--unique", "paths"]
        
        domains_result = subprocess.run(domains_cmd, input=urls_input, capture_output=True, text=True, timeout=300)
        paths_result = subprocess.run(paths_cmd, input=urls_input, capture_output=True, text=True, timeout=300)
        
        domains = []
        paths = []
        
        if domains_result.returncode == 0:
            domains = [line.strip() for line in domains_result.stdout.splitlines() if line.strip()]
        
        if paths_result.returncode == 0:
            paths = [line.strip() for line in paths_result.stdout.splitlines() if line.strip()]
        
        # Save results to JSON file
        results_data = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "input_file": file_path,
            "total_urls": len(urls),
            "unique_domains": domains,
            "unique_paths": paths,
            "parameters": parameters,
            "summary": {
                "total_parameters": len(parameters),
                "unique_parameter_names": len(set(p["name"] for p in parameters)),
                "domains_discovered": len(domains),
                "paths_discovered": len(paths)
            }
        }
        
        with open(output_file, "w") as outfile:
            json.dump(results_data, outfile, indent=2)
        
        return {
            "status": "success",
            "file_path": file_path,
            "parameters": parameters,
            "total_urls_processed": len(urls),
            "unique_parameters": len(set(p["name"] for p in parameters)),
            "message": f"Found {len(parameters)} parameters with unfurl. Results saved to {output_file}"
        }
    
    except subprocess.TimeoutExpired:
        print("unfurl command timed out after 5 minutes")
        return {
            "status": "error",
            "file_path": file_path,
            "error_message": "unfurl command timed out after 5 minutes"
        }
    except FileNotFoundError as e:
        print(f"File not found: {str(e)}")
        return {
            "status": "error",
            "file_path": file_path,
            "error_message": f"Input file not found: {str(e)}"
        }
    except Exception as e:
        print(f"Unexpected error running unfurl: {str(e)}")
        return {
            "status": "error",
            "file_path": file_path,
            "error_message": f"Unexpected error running unfurl: {str(e)}"
        }

def vulnerability_scan(target: str) -> dict:
    """
    Perform vulnerability scanning on a target using nuclei.
    
    Args:
        target: Target domain, URL, or IP address
    
    Returns:
        Dictionary containing vulnerability scan results
    """
    try:
        # Check if nuclei is installed
        try:
            subprocess.run(["nuclei", "-version"], capture_output=True, check=True, timeout=10)
        except (subprocess.CalledProcessError, FileNotFoundError):
            return {
                "status": "error",
                "target": target,
                "error_message": "nuclei is not installed or not in PATH. Please install it first."
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "target": target,
                "error_message": "nuclei version check timed out"
            }
        
        # Update nuclei templates (optional but recommended)
        try:
            print("Updating nuclei templates...")
            update_result = subprocess.run(["nuclei", "-update-templates"], 
                                         capture_output=True, text=True, timeout=120)
            if update_result.returncode == 0:
                print("Templates updated successfully")
            else:
                print("Template update failed, proceeding with existing templates")
        except (subprocess.TimeoutExpired, Exception):
            print("Template update skipped, proceeding with existing templates")
        
        # Create output directory
        output_dir = "vulnerability_scan"
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, f"nuclei_{target.replace('://', '_').replace('/', '_')}.json")
        
        # Run nuclei command with correct flags
        cmd = [
            "nuclei",
            "-target", target,  # Correct flag for target specification
            "-t", "cves/,vulnerabilities/,misconfigurations/",  # Template directories with correct paths
            "-s", "critical,high,medium",  # Correct severity flag (-s instead of -severity)
            "-je", output_file,  # JSON export to file (-je instead of -json -o)
            "-silent"  # Only show findings
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # 30 minutes timeout
        
        if result.returncode != 0:
            return {
                "status": "error",
                "target": target,
                "error_message": f"nuclei command failed: {result.stderr}"
            }
        
        # Read and parse the output file
        vulnerabilities = []
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, "r") as file:
                for line in file:
                    try:
                        vuln = json.loads(line.strip())
                        info = vuln.get("info", {})
                        vulnerabilities.append({
                            "name": info.get("name", "Unknown"),
                            "severity": info.get("severity", "Unknown"),
                            "template": vuln.get("template", vuln.get("template-id", "")),
                            "template_id": vuln.get("template-id", ""),
                            "matcher_name": vuln.get("matcher-name", ""),
                            "description": info.get("description", ""),
                            "reference": info.get("reference", []),
                            "tags": info.get("tags", []),
                            "classification": info.get("classification", {}),
                            "url": vuln.get("matched-at", vuln.get("host", "")),
                            "type": vuln.get("type", ""),
                            "timestamp": vuln.get("timestamp", ""),
                            "request": vuln.get("request", ""),
                            "response": vuln.get("response", "")
                        })
                    except json.JSONDecodeError:
                        continue
        
        # Group vulnerabilities by severity
        severity_counts = {
            "critical": len([v for v in vulnerabilities if v["severity"].lower() == "critical"]),
            "high": len([v for v in vulnerabilities if v["severity"].lower() == "high"]),
            "medium": len([v for v in vulnerabilities if v["severity"].lower() == "medium"]),
            "low": len([v for v in vulnerabilities if v["severity"].lower() == "low"]),
            "info": len([v for v in vulnerabilities if v["severity"].lower() == "info"])
        }
        
        return {
            "status": "success",
            "target": target,
            "timestamp": datetime.datetime.now().isoformat(),
            "vulnerabilities": vulnerabilities[:50],  # Limit to 50 vulnerabilities
            "total_vulnerabilities": len(vulnerabilities),
            "severity_counts": severity_counts,
            "stdout_output": len(result.stdout.split("\n")),
            "message": f"Found {len(vulnerabilities)} vulnerabilities. Full results saved to {output_file}"
        }
        
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "target": target,
            "error_message": "nuclei command timed out after 30 minutes"
        }
    except Exception as e:
        return {
            "status": "error",
            "target": target,
            "error_message": f"Unexpected error: {str(e)}"
        }

def run_github_recon(target: str, tools: str = "all") -> dict:
    """
    Perform GitHub reconnaissance on a target using TruffleHog for secret detection.
    
    Args:
        target: The target organization, repository, or search query
        tools: Legacy parameter (only trufflehog is used)
    
    Returns:
        Dictionary containing reconnaissance results from GitHub using TruffleHog
    """
    # Only use TruffleHog for GitHub reconnaissance
    available_tools = ["trufflehog"]
    selected_tools = ["trufflehog"]
    
    # Create output directory for results
    output_dir = "github_recon_results"
    os.makedirs(output_dir, exist_ok=True)
    
    # Store results for each tool
    all_results = {}
    findings_summary = {}
    
    for tool in selected_tools:
        try:
            print(f"Running {tool} on {target}...")
            
            # Run TruffleHog (only tool used for GitHub recon)
            if tool == "trufflehog":
                result = _run_trufflehog(target, output_dir)
            else:
                continue  # Skip any other tools
            
            all_results[tool] = result
            
            # Add to findings summary
            if result["status"] == "success":
                findings_summary[tool] = {
                    "total_findings": result.get("total_findings", 0),
                    "output_file": result.get("output_file", "")
                }
            else:
                findings_summary[tool] = {
                    "error": result.get("error_message", "Unknown error")
                }
                
        except Exception as e:
            all_results[tool] = {
                "status": "error",
                "target": target,
                "tool": tool,
                "error_message": f"Error running {tool}: {str(e)}"
            }
            findings_summary[tool] = {
                "error": f"Error running {tool}: {str(e)}"
            }
    
    # Calculate total findings across all tools
    successful_tools = sum(1 for tool, result in all_results.items() if result.get("status") == "success")
    failed_tools = sum(1 for tool, result in all_results.items() if result.get("status") == "error")
    total_findings = sum(result.get("total_findings", 0) for result in all_results.values())
    
    return {
        "status": "success" if successful_tools > 0 else "error",
        "target": target,
        "timestamp": datetime.datetime.now().isoformat(),
        "successful_tools": successful_tools,
        "failed_tools": failed_tools,
        "total_findings": total_findings,
        "findings_summary": findings_summary,
        "tool_results": all_results,
        "message": f"Ran {len(selected_tools)} GitHub reconnaissance tools on {target}. Found {total_findings} potential issues."
    }

def _run_trufflehog(target: str, output_dir: str) -> dict:
    """
    Run TruffleHog to find secrets in GitHub repositories.
    """
    try:
        # Check if trufflehog is installed
        try:
            subprocess.run(["trufflehog", "--help"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            return {
                "status": "error",
                "target": target,
                "error_message": "trufflehog is not installed or not in PATH. Please install it first."
            }
        
        # Determine if target is a GitHub URL or organization/repo
        if not target.startswith("http"):
            # Convert to GitHub URL format
            if "/" in target:  # Likely org/repo format
                github_url = f"https://github.com/{target}.git"
            else:  # Likely just an organization
                github_url = f"https://github.com/{target}"
        else:
            github_url = target
            
        # Define output file
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        output_file = os.path.join(output_dir, f"trufflehog_{timestamp}.json")
        
        # Run trufflehog command
        cmd = [
            "trufflehog", 
            "github", 
            "--repo", github_url,
            "--json",
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # 30 minutes timeout
        
        # Parse and save the output
        if result.stdout:
            findings = []
            
            # TruffleHog outputs one JSON object per line
            for line in result.stdout.splitlines():
                if line.strip():
                    try:
                        finding = json.loads(line.strip())
                        findings.append(finding)
                    except json.JSONDecodeError:
                        continue
            
            # Save findings to file
            with open(output_file, "w") as file:
                json.dump(findings, file, indent=2)
            
            return {
                "status": "success",
                "target": target,
                "total_findings": len(findings),
                "findings": findings[:10],  # Limit to first 10 findings in response
                "stdout_output": len(result.stdout.split("\n")),
                "message": f"Found {len(findings)} potential secrets with trufflehog. Results saved to {output_file}"
            }
        else:
            # No findings
            with open(output_file, "w") as file:
                json.dump([], file)
                
            return {
                "status": "success",
                "target": target,
                "total_findings": 0,
                "findings": [],
                "stdout_output": len(result.stdout.split("\n")),
                "message": f"No secrets found with trufflehog in {target}."
            }
            
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "target": target,
            "error_message": "trufflehog scan timed out after 30 minutes"
        }
    except Exception as e:
        return {
            "status": "error",
            "target": target,
            "error_message": f"Unexpected error during trufflehog scan: {str(e)}"
        }

def verify_tools(display_results: Optional[bool] = None) -> dict:
    """
    Verify availability of all tools used in the reconnaissance agent.
    Only runs when specifically requested by the user.
    
    Args:
        display_results: True to show all, False to hide, None for auto (default)
    
    Returns:
        Dictionary containing tool verification results with installation suggestions
    """
    
    # Define all tools used in the codebase with their verification commands and installation instructions
    tools_config = {
        # Subdomain enumeration tools
        "subfinder": {
            "check_cmd": ["subfinder", "-version"],
            "install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "description": "Fast subdomain discovery tool"
        },
        "skanuvaty": {
            "check_cmd": ["skanuvaty", "--help"],
            "install": "pip install skanuvaty",
            "description": "Fast subdomain enumeration tool"
        },
        "bbot": {
            "check_cmd": ["bbot", "--version"],
            "install": "pip install bbot",
            "description": "Recursive internet scanner for Bug Bounty reconnaissance"
        },
        "csprecongo": {
            "check_cmd": ["csprecongo", "-h"],
            "install": "go install github.com/edoardottt/csprecon/cmd/csprecon@latest",
            "description": "Discover new target domains using Content Security Policy"
        },
        "shosubgo": {
            "check_cmd": ["shosubgo", "-h"],
            "install": "go install github.com/incogbyte/shosubgo@latest",
            "description": "Small tool to Grab subdomains using Shodan API"
        },
        "scilla": {
            "check_cmd": ["scilla", "--help"],
            "install": "go install github.com/edoardottt/scilla/cmd/scilla@latest",
            "description": "Information gathering tool for DNS/subdomain/port enumeration"
        },
        
        # URL discovery tools
        "waymore": {
            "check_cmd": ["waymore", "-h"],
            "install": "pip install waymore",
            "description": "Find way more from the Wayback Machine"
        },
        "gau": {
            "check_cmd": ["gau", "--version"],
            "install": "go install github.com/lc/gau/v2/cmd/gau@latest",
            "description": "Fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl"
        },
        "waybackurls": {
            "check_cmd": ["waybackurls", "-h"],
            "install": "go install github.com/tomnomnom/waybackurls@latest",
            "description": "Fetch all the URLs that the Wayback Machine knows about for a domain"
        },
        
        # Port scanning tools
        "nmap": {
            "check_cmd": ["nmap", "--version"],
            "install": "apt-get install nmap # Ubuntu/Debian, or brew install nmap # macOS",
            "description": "Network exploration tool and security scanner"
        },
        "smap": {
            "check_cmd": ["smap", "-h"],
            "install": "go install github.com/s0md3v/smap/cmd/smap@latest",
            "description": "Passive nmap-like scanner built with shodan.io"
        },
        
        # JavaScript link extraction
        "linkfinder": {
            "check_cmd": ["python3", "linkfinder.py", "--help"],
            "install": "git clone https://github.com/GerbenJavado/LinkFinder.git; cd LinkFinder; pip3 install -r requirements.txt",
            "description": "Python script that finds endpoints in JavaScript files"
        },
        
        # Crawling tools
        "katana": {
            "check_cmd": ["katana", "--version"],
            "install": "CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest",
            "description": "Next-generation crawling and spidering framework"
        },
        
        # Broken link checking
        "blc": {
            "check_cmd": ["blc", "--help"],
            "install": "npm install broken-link-checker -g",
            "description": "Find broken links, missing images, etc within your HTML"
        },
        
        # Social media reconnaissance
        "socialhunter": {
            "check_cmd": ["socialhunter", "-h"],
            "install": "go install github.com/utkusen/socialhunter@latest",
            "description": "Crawls the website and finds broken social media links"
        },
        
        # Parameter scanning tools
        "fallparams": {
            "check_cmd": ["fallparams", "-h"],
            "install": "go install github.com/ImAyrix/fallparams@latest",
            "description": "Find All Parameters - Tool to crawl pages, find potential parameters and generate a custom target wordlist"
        },
        "unfurl": {
            "check_cmd": ["unfurl", "-h"],
            "install": "go install github.com/tomnomnom/unfurl@latest",
            "description": "Pull out bits of URLs provided on stdin"
        },
        
        # Vulnerability scanning
        "nuclei": {
            "check_cmd": ["nuclei", "-version"],
            "install": "go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
            "description": "Fast and customizable vulnerability scanner"
        },
        
        # GitHub reconnaissance tools
        "trufflehog": {
            "check_cmd": ["trufflehog", "--help"],
            "install": "go install github.com/trufflesecurity/trufflehog/v3@latest",
            "description": "Find and verify credentials"
        }
    }
    
    # Check tool availability
    available_tools = []
    missing_tools = []
    tool_status = {}
    
    for tool_name, config in tools_config.items():
        try:
            # Try the primary check command
            result = subprocess.run(config["check_cmd"], capture_output=True, text=True, timeout=10)
            
            # A tool is considered available if:
            # 1. Command executed successfully (returncode 0), OR
            # 2. Command failed but produced output (meaning tool exists but command failed)
            # 3. stderr contains expected patterns indicating tool exists
            tool_available = False
            output_text = ""
            
            if result.returncode == 0:
                tool_available = True
                output_text = result.stdout.strip()[:100] if result.stdout.strip() else "Available"
            elif result.stdout.strip() or result.stderr.strip():
                # Tool exists but command may have failed (common with --help commands)
                # Check if stderr contains "command not found" or similar
                stderr_lower = result.stderr.lower()
                if "command not found" in stderr_lower or "not found" in stderr_lower or "no such file" in stderr_lower:
                    tool_available = False
                else:
                    tool_available = True
                    output_text = (result.stdout.strip() or result.stderr.strip())[:100]
            
            if tool_available:
                available_tools.append(tool_name)
                tool_status[tool_name] = {
                    "status": "available",
                    "description": config["description"],
                    "version_info": output_text or "Available"
                }
            else:
                missing_tools.append(tool_name)
                tool_status[tool_name] = {
                    "status": "missing",
                    "description": config["description"],
                    "install_command": config["install"],
                    "error": result.stderr.strip()[:100] if result.stderr.strip() else "Tool not found"
                }
        except FileNotFoundError:
            # Tool definitely not found
            missing_tools.append(tool_name)
            tool_status[tool_name] = {
                "status": "missing",
                "description": config["description"],
                "install_command": config["install"],
                "error": "Tool not found in PATH"
            }
        except subprocess.TimeoutExpired:
            # Tool exists but command timed out - consider it available
            available_tools.append(tool_name)
            tool_status[tool_name] = {
                "status": "available",
                "description": config["description"],
                "version_info": "Available (command timed out)"
            }
        except Exception as e:
            # Unexpected error
            missing_tools.append(tool_name)
            tool_status[tool_name] = {
                "status": "error",
                "description": config["description"],
                "install_command": config["install"],
                "error": f"Verification error: {str(e)}"
            }
    
    # Create summary
    total_tools = len(tools_config)
    available_count = len(available_tools)
    missing_count = len(missing_tools)
    
    result = {
        "status": "success",
        "summary": {
            "total_tools": total_tools,
            "available_tools": available_count,
            "missing_tools": missing_count,
            "availability_percentage": round((available_count / total_tools) * 100, 1)
        },
        "available_tools": available_tools,
        "missing_tools": missing_tools,
        "tool_details": tool_status,
        "recommendations": []
    }
    
    # Add recommendations based on missing tools
    if missing_count > 0:
        result["recommendations"].append(f"{missing_count} tools are missing. Install them for full functionality.")
        
        # Group missing tools by installation method
        go_tools = []
        pip_tools = []
        npm_tools = []
        manual_tools = []
        
        for tool in missing_tools:
            install_cmd = tools_config[tool]["install"]
            if install_cmd.startswith("go install"):
                go_tools.append(tool)
            elif install_cmd.startswith("pip install"):
                pip_tools.append(tool)
            elif install_cmd.startswith("npm install"):
                npm_tools.append(tool)
            else:
                manual_tools.append(tool)
        
        if go_tools:
            result["recommendations"].append(f"Go tools missing: {', '.join(go_tools)} - Install Go if needed")
        if pip_tools:
            result["recommendations"].append(f"Python tools missing: {', '.join(pip_tools)} - Install Python/pip if needed")
        if npm_tools:
            result["recommendations"].append(f"Node.js tools missing: {', '.join(npm_tools)} - Install Node.js/npm if needed")
        if manual_tools:
            result["recommendations"].append(f"Manual installation needed: {', '.join(manual_tools)}")
    else:
        result["recommendations"].append("All tools are available! Your reconnaissance setup is complete.")
    
    return handle_results(result, "verify_tools", "", display_results)

if HAS_GOOGLE_ADK:
    root_agent = Agent(
    name="recon_agent",
    model="gemini-2.0-flash",
    #model=LiteLlm(model="gpt-4o", api_key=os.getenv("OPENAI_API_KEY")),
    description="Agent to perform comprehensive reconnaissance including subdomain enumeration with multiple tools, IP range discovery, URL discovery with various tools, port scanning with various tools, cloud reconnaissance, JavaScript link discovery, crawling, vulnerability scanning, GitHub reconnaissance, parameter scanning, broken link checking, and tool verification",
    instruction="""You are a powerful reconnaissance agent who can:
    1. Find subdomains for a target domain using various tools (subfinder, skanuvaty, bbot, csprecongo, shosubgo, scilla)
    2. Get historical and archived URLs of a target domain using various tools (waymore, gau, waybackurls)
    3. Resolve subdomains to IPs from a saved file and perform port scanning
    4. Perform cloud reconnaissance on a target domain
    5. Find JavaScript links from subdomains in a file
    6. Crawl subdomains from a file to discover endpoints
    7. Perform vulnerability scanning on a target domain or IP address
    8. Scan ports using a choice of tools (nmap, smap) on IP addresses from a file or a single target, with custom port specifications
    9. Perform GitHub reconnaissance using TruffleHog to discover sensitive information
    10. Scan for URL parameters from a file of subdomains using various tools (fallparams, unfurl)
    11. Check for broken links on a target domain or URL using various tools (blc, socialhunter)
    12. Perform individual broken link checking using blc tool
    13. Conduct social media reconnaissance to find broken social media links
    14. Search for APIs and documentation on SwaggerHub and Postman
    15. Verify tool availability and get installation suggestions for missing reconnaissance tools

    IMPORTANT BEHAVIORAL GUIDELINES:
    - For multi-tool functions (subdomain enumeration, port scanning, URL discovery, GitHub reconnaissance, parameter scanning, broken link checking), ALWAYS ask the user which specific tools they want to use unless they explicitly specify in their request
    - When user says "all", run all available tools sequentially using the existing tools parameter functionality
    - Present available tool options clearly and let user choose specific tools or "all"
    - Never assume which tools to use - always confirm with the user first
    - If user provides a specific tool name in their request, use that tool without asking
    - Be interactive and helpful in guiding tool selection decisions""",
    tools=[
        get_subdomains,
        get_ip_ranges, 
        get_archive_urls, 
        run_port_scan,
        resolve_subdomains,
        cloud_recon,
        get_js_links,
        crawl_target,
        vulnerability_scan,
        run_github_recon,
        scan_parameters,
        check_broken_links,
        check_broken_links_blc,
        social_media_recon,
        api_recon,
        verify_tools
    ],
)
else:
    root_agent = None
    print('Google ADK not available. Agent not created.')
