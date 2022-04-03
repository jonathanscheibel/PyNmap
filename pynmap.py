#!.venv/bin/python

import argparse
import os
import json
import logging
import subprocess

from nmap import PortScanner, PortScannerError
from decouple import config


VERSION = 1.0
DEBUG = config('DEBUG', cast=bool)
NAME_SCRIPT = os.path.basename(__file__)
OBJECT_NONE = 'O objeto não foi passado adequadamente por parâmetro!'

class ExceptionDefault(Exception):
    """
    Este é apenas um exemplo para tratamento de exeções do pynmap.
    Para criar exceções específicas, favor herdar ExceptionDefault.
    """ 
    def __init__(self, msg=''):
        self.msg = msg
        logging.error(f'Ocorreu exceção tratada no pynmap! {msg}') 
    
    def __str__(self):
        return self.msg



def report_console(report):
        """Exporta o relatório para o modo simplório, para o console"""
        def wrapper(ref, nm):            
            if nm is None:                
                raise ExceptionDefault(OBJECT_NONE)
            result = ''
            for host in nm.all_hosts():                                
                result += '='*80 + '\n'
                result += 'Host: %s (%s)\tStatus: %s \n' % (host, nm[host].hostname(), nm[host].state())             
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in lport:                                               
                        result += 'Porta: %s\tStatus: %s\tNome: %s\tProduto: %s\n' % (
                            port, nm[host][proto][port]['state'], 
                            nm[host][proto][port]['name'],
                            nm[host][proto][port]['product']
                        )                
            return result            
        return wrapper

def report_xml(self):
        """Exporta o relatório direcionando-o para a normalização XML."""
        def wrapper(ref, nm):            
            if nm is None:                
                raise ExceptionDefault(OBJECT_NONE)
            return ref.nm.get_nmap_last_output().decode('utf-8')
        return wrapper

def report_json(self):
        """Exporta o relatório direcionando-o para a normalização JSON."""
        def wrapper(ref, nm):            
            if nm is None:                
                raise ExceptionDefault(OBJECT_NONE)
            return json.dumps(ref.dict_report)
        return wrapper

def report_csv(report):
    """Exporta o relatório direcionando-o para a normalização CSV."""
    def wrapper(ref, nm):            
            if nm is None:                
                raise ExceptionDefault(OBJECT_NONE)
            return nm.csv()
    return wrapper

class PyNmap():
    def __init__(self, check_nmap=True):        
        self.log_level = logging.ERROR
        if DEBUG:
            self.log_level = logging.DEBUG
        logging.basicConfig(filename='pynmap.log', encoding='utf-8', level=self.log_level)
        self.log = logging.getLogger('root')

        if check_nmap:
            try:
                self.check_nmap_into_system()
            except Exception as err:
                print('Erro: ', err)
                exit(err)        

        self.my_parser = argparse.ArgumentParser(
            prog=NAME_SCRIPT,
            description='''Script em python que recebe um (ou uma lista) de hosts por parâmetro, 
                e realiza um port scan através de integração do python e nmap. O código é 
                resiliente a travamentos do nmap, pois caso ele não retorne a resposta 
                em até 1 minuto (ou tempo parametrizado), a ação é interrompida retornando o
                status de erro. O script está preparado para diferentes outputs.
                '''
            )

        self.my_parser.version = VERSION
        self.my_parser.add_argument('-hosts', metavar='hosts', required=True, action='store', nargs='+', 
            help='Envie um ou mais destinos')
        self.my_parser.add_argument('-ports', metavar='ports', action='store', default='1-1024', 
            help='Defina as portas alvo (em sintaxe nmap)')
        self.my_parser.add_argument('-arguments', metavar='arguments', action='store', 
            default='-v',
            help='Envie para o nmap expressamente os argumentos')
        self.my_parser.add_argument('-arguments_conf', metavar='arguments_conf', action='store', 
            default='NMAP_DEFAULT_QUICK_SCAN', 
            help='Envie para o nmap a configuração do argumento (verifique o file virtual enviroment)')
        self.my_parser.add_argument('-t', '-timeout', '--timeout', metavar='timeout', action='store', 
            default=60, type=int, 
            help='Timeout em segundos. (Padrao: 60 segundos)')
        self.my_parser.add_argument('-output', '--output', '-o', metavar='output', action='store', default='console', 
            help='Defina o padrão de saída')    
        self.my_parser.add_argument('-v', '-version', '--version', '-V', action='version', 
            version=f'%(prog)s {VERSION}', 
            help=f'Versão do {NAME_SCRIPT}')

        self.args = self.my_parser.parse_args()
        self.args.arguments_conf = config(self.args.arguments_conf)

        self.nm = None
        self.dict_report = {}
        self.log.debug('Parâmetros: ' + str(vars(self.args).items()))        

    def system_call(self, str_command):
        p = subprocess.Popen([str_command], stdout=subprocess.PIPE, shell=True)
        return p.stdout.read().decode().strip()

    def check_nmap_into_system(self):
        CMD_CHECK_NMAP = 'whereis nmap | wc -c' 
        qtd_char = int(self.system_call(CMD_CHECK_NMAP))        
        if qtd_char <= 7:        
            raise ExceptionDefault(
                f'''Para execução do {NAME_SCRIPT} é necessário o pacote nmap instalado.'''
            )

    def scan(self):   
        '''Função que utiliza a lib para realizar o trabalho de scaneamento'''               
        # TODO Criar opção de targets via arquivo
        self.dict_report = self.nm.scan(hosts=' '.join(self.args.hosts), # ports=self.args.ports, 
            arguments=self.args.arguments + ' ' + self.args.arguments_conf, 
            timeout=self.args.timeout)                    
        self.log.debug('Comando nmap: ' + self.nm.command_line())
        
    
    # @report_csv
    # @report_xml
    # @report_json
    @report_console
    def report_default(self, nm):               
        """
        Escolha o decorador de acordo com a saída necessária.
        Foi realizada implementação para diferentes tipos de output. Caso haja necessidade
        implemente o tipo de saida, e decore aqui. 

        Alguns exemplos: @report_csv, @report_xml, @report_json, [...]
        """
        pass

    def exec(self):
        """
        Procedimento principal para chamada da rotina automatizada de port scan.    
        Configure DEBUG para rastrear parametros e comandos desejados via log.
        """    
        self.nm = PortScanner()
        try:                
            self.scan()      

            outputs = {
                'console': report_console(self.nm),
                'xml': report_xml(self.nm),
                'csv': report_csv(self.nm),
                'json': report_json(self.nm)
            }                
            try:
                report_output = outputs.get(self.args.output)(self, self.nm)                        
                print(report_output) # Envia para saída no padrão escolhido pelo usuário
            except Exception as err:
                raise ExceptionDefault('O padrão de output informado é inválido!')
            
        except PortScannerError as e: 
            raise ExceptionDefault('Status: {0} - ({1})'.format(e, 'Erro original'))         

    def main(self):
        try:
            self.exec()
        except Exception as err:
            print(err)

if __name__ == "__main__":
    PyNmap().main()


