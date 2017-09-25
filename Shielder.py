import requests
import base64
import json
import datetime
import getpass

# Function to encode the credentials em base64 as required by the IPS SDK // Funçao para fazer o encode em base64 das credenciais
def fn_base64encode(u,p):
    userPass = '%s:%s' % (u,p)
    return base64.b64encode(bytes(userPass,'utf-8'))

# Function to convert the data on the body response to a json (dict type) // Funcao para converter a resposta das requisiçoes em dicionarios
def fn_convert_response_to_json(rsp):
    return json.loads(str(rsp,'utf-8'))
# Function to request a resource with GET and return the response content in json format // Funcao para requisitar um recurso com metodo GET e retornar a resposta em json
def fn_get_request(resource):
    get_req = requests.get(url+resource, headers = headers)
    return fn_convert_response_to_json(get_req.content)

# Function to request a resource with POST and return the response content in json format // Funcao para requisitar um recurso com metodo POST e retornar a resposta em json
def fn_post_request(resource,data):
    post_req = requests.post(url+resource, headers = headers, data = json.dumps(data))
    return post_req.content

# Function to logoff the session // Funcao para encerrar a sessao
def fn_logoff_session():
    logoff = requests.delete(url+'session', headers = headers)
    return fn_convert_response_to_json(logoff.content)

# Function to triage the alerts in the attack log and list a summary of the attacks triggered // Funcao para triar os alertas do attack log e listar os ataques que foram detectados
def fn_triage_Attacks(alertList,startTime,endTime,triggeredAttacks,count):
    f = open("triggeredAttacks_%s_to_%s.txt" % (startTime.strftime("%Y-%m-%d--%H-%M"),endTime.strftime("%Y-%m-%d--%H-%M")),"ab")
    attacks_triggered = triggeredAttacks
    for alert in alertList: #For loop to analyse all the alerts and get the list of attacks triggered // Laco for para analisar os alertas e pegar os ataques detectados
        if alert ['name'] not in attacks_triggered:
            attacks_triggered.append(alert ['name'])
            log = 'Count %s --- Attack: %s was triggered and has been registered not to block without further analysis.' % (count,alert ['name'])
            f.write (bytes(log+'\n','utf-8'))
            print (log)
            print ()
    return attacks_triggered
    f.close()

# Function to get the ID from a element base on its name // Funcao para pegar o ID de um elemento baseado em seu nome
def fn_getID_fromName(item,itemList,itemName,itemId,selectedItem):
    for item in itemList:
        if item [itemName] == selectedItem:
            return item [itemId]

# Function to filter alerts in attack log and return only the ones that hasn't been blocked ow smartblocked // Funcao para filtrar os alertar do attack log e retornar apenas os alertas sem bloqueio
def fn_filter_alerts(alertList):
    BlockingResults = ['Attack Blocked','Attack SmartBlocked','Blocking Simulated (Attack Blocked)','Blocking Simulated (Attack SmartBlocked)']
    filteredAlerts = []
    for alert in alertList:
        if alert ['event'] ['result'] not in BlockingResults:
            filteredAlerts.append(alert)
    return filteredAlerts

# Function to get the desired domain from the Manager and return its ID // Funcao para consultar o dominio desejado na Manager e retornar seu ID
def fn_get_domain(domain_name):
    domains = fn_get_request('domain') #Get all the domains // Pega todos os dominios
    domain = domains ['DomainDescriptor'] #Get the list of domains from the response of the previous request // Pega a lista com os dominios da resposta da requisicao anterior
    if domain ['name'] == domain_name: # Condition to get domain ID from domain_name // Condicao para pegar o ID do domínio a partir do Nome do domínio informado
        return domain ['id']
    else: # Condition to get domain ID from domain_name in Child Domains // Condicao para pegar o ID do domínio a partir do Nome do domínio informado nos dominios-filhos
        childdomains = domain ['childdomains']
        for childdomain in childdomains:
            if childdomain ['name'] == domain_name:
                return childdomain ['id']
            else:
                print ('It is only allowed to search for the root domain or its child domains (first inheritance level)!')
                break

# Function to get the desired sensor from the Manager and return its ID // Funcao para consultar o sensor desejado na Manager e retornar seu ID
def fn_get_sensor(sensor_name,domain_id):
    sensors = fn_get_request('sensors?domain=%s' % domain_id) #Get all the sensors from the domain // Pega todos os sensores do dominio
    sensorsList = sensors ['SensorDescriptor'] #Get the list of sensors // Pega a lista dos sensores
    return fn_getID_fromName('sensor',sensorsList,'name','sensorId',sensor_name) #Get the sensor's ID // Pega o ID so sensor

# Function to get the desired interface from the Manager and return its ID // Funcao para consultar a interface desejada na Manager e retornar seu ID
def fn_get_interface(interface_name,sensor_id):
    interfaces = fn_get_request('sensor/%s' % sensor_id) #Get all the interfaces from the sensor // Pega todas interfaces do sensor
    interfaceList = interfaces ['SensorInfo'] ['Interfaces'] ['InterfaceInfo'] #Get the list of interfaces // Pega a lista de interfaces
    return fn_getID_fromName ('interface',interfaceList,'name','vidsId',interface_name) #Get the Interface's ID // Pega o ID da interface

# Function to get the desired policy from the selected interface // Funcao para pegar a policy da interface selecionada
def fn_get_policy(sensor_id,interface_id,interface_name):
    interfacePolicy = fn_get_request('sensor/%s/interface/%s/localipspolicy/' % (sensor_id,interface_id)) #Get the local policy from the selected interface // Pega a policy local da interface
    date = datetime.datetime.now().strftime("%Y-%m-%d--%H-%M-%S") #Get the current time // Pega o horario atual
    f = open("original-policy--interfaceID_%s--%s.txt" % (interface_id,date),"w")
    f.write (str(interfacePolicy))
    f.close()
    print ('Original policy exported successfully...')
    return interfacePolicy

# Function to evaluate the attacks in the policy and set the ones that were not detected in the analysed period to blocking mode // Funcao para avaliar os ataques da policy e bloquear os que nao foram detectados no periodo analisado
def fn_block_sigs(original_policy,interface_id,triggeredAttacks):
    AttackList = original_policy ['PolicyDescriptor'] ['AttackCategory'] ['ExpolitAttackList'] #Get the list with all attacks in the policy // Pega a lista com todos os ataques da policy
    print ('%s attacks found to be analysed...' % len(AttackList))
    date = datetime.datetime.now() #Get the current time // Pega o horario atual
    attacksChangeLog = open("Attacks-Change-Log--interfaceID_%s--%s.txt" % (interface_id,date.strftime("%Y-%m-%d--%H-%M-%S")),"a") #Opens the file where the changes on the policy will be logged // Abre o arquivo onde as alteracoes na policy serao registradas
    # For loop to get the attacks that has blocking option and are not set to block yet and were not triggered in the last period measured // Laco for para pegar os ataques que possuem opção de bloqueio e ainda não estão em modo de bloqueio e nao foram detectados no ultimo periodo
    changeAttackCount = 0
    for attack in AttackList:
        if attack ['severity'] in severityId and attack ['AttackResponse'] ['blockingOption'] in blockingOptions and attack ['AttackResponse'] ['blockingOption'] in nonBlockingOptions and attack ['attackName'] not in triggeredAttacks:
            changeAttackCount += 1
            oldBlockingOption = attack ['AttackResponse'] ['blockingOption']
            oldIsBlockingOptionCustomized = attack ['AttackResponse'] ['isBlockingOptionCustomized']
            oldIsAttackCustomized = attack ['isAttackCustomized']
            attack ['AttackResponse'] ['blockingOption'] = 'ENABLE'
            attack ['AttackResponse'] ['isBlockingOptionCustomized'] = True
            attack ['AttackResponse'] ['TimeStamp'] = date.strftime("%Y-%m-%d %H:%M:%S.000")
            attack ['isAttackCustomized'] = True
            log = 'Time: %s, User: %s, Change number: %s, Attack %s, changed from blockingOption: %s and isBlockingOptionCustomized: %s and isAttackCustomized: %s to blockingOption: %s and isBlockingOptionCustomized: %s and isAttackCustomized: %s' % (date,user,changeAttackCount,attack['attackName'],oldBlockingOption,oldIsBlockingOptionCustomized,oldIsAttackCustomized, attack ['AttackResponse'] ['blockingOption'],attack ['AttackResponse'] ['isBlockingOptionCustomized'],attack ['isAttackCustomized'])
            attacksChangeLog.write (log+'\n')
            print (log)
    log = '%s attacks were set to blocking mode of %s attacks in the policy...' % (changeAttackCount,len(AttackList))
    attacksChangeLog.write (log)
    print (log)
    attacksChangeLog.close() #Closes the file where the changes on the policy will be logged // Fecha o arquivo onde as alteracoes na policy serao registradas
    return AttackList

# Function to update the policy that will be imported back to the Manger with the blocked attacks // Funcao para atualizar a policy que sera importada de volta para a Manager com os ataques bloqueados
def fn_update_policy(interfacePolicy,AttackListBlocked,interface_id):
    interfacePolicy ['PolicyDescriptor'] ['AttackCategory'] ['ExpolitAttackList'] = AttackListBlocked #Updates the content of the policy that will be replaced // Atualiza o conteudo da policy que sera substituida
    date = datetime.datetime.now() #Get the current time // Pega o horario atual
    interfacePolicy ['PolicyDescriptor'] ['Timestamp'] = date.strftime("%Y-%m-%d %H:%M:%S.000")
    interfacePolicy ['PolicyDescriptor'] ['VersionNum'] += 1
    f = open("new-policy--interfaceID_%s--%s.txt" % (interface_id,date.strftime("%Y-%m-%d--%H-%M-%S")),"w")
    f.write (str(interfacePolicy))
    f.close()
    print ("New policy configured and ready to be imported...")
    return interfacePolicy

# Function to apply the new policy in the selected interface
def fn_apply_new_policy(interface_name,sensor_id,interface_id,new_policy):
    confirmation = input("Update policy of the interface %s with attacks in blocking mode? (Y/n)" % interface_name)
    if confirmation in ['y','Y','']:
        print ("Applying new policy to the selected interface...")
        policy_updated = fn_post_request('sensor/%s/interface/%s/localipspolicy/' % (sensor_id,interface_id),new_policy)
        return policy_updated
    elif confirmation in ['n','N']:
        print ("Aborting policy block...")
    else:
        print ("Invalid option!")
        fn_apply_new_policy()


# Function to select a Local Interface IPS Policy analyse it set the some attacks to blocking mode and update the policy in the Manager // Funcao para selecionar uma policy local de interface, analisa-la, bloquear alguns ataques e atualizar a policy na Manager
def fn_shield_policy():
    domain_name = input ('Insert the Domain: ') #Name of the Domain that will be modified // Nome do domínio onde serao feitos os bloqueios
    domain_id = fn_get_domain(domain_name)
    sensor_name = input('Insert sensor: ')
    sensor_id = fn_get_sensor(sensor_name,domain_id)
    interface_name = input('Insert interface: ')
    interface_id = fn_get_interface(interface_name,sensor_id)
    original_policy = fn_get_policy(sensor_id,interface_id,interface_name)
    AttackListBlocked = fn_block_sigs(original_policy,interface_id,triggeredAttacks)
    new_policy = fn_update_policy(original_policy,AttackListBlocked,interface_id)
    updateLocalPolicy = fn_apply_new_policy(interface_name,sensor_id,interface_id,new_policy)
    print (updateLocalPolicy)

# Function to get the list of triggeredAttacks within a specified period of time // Funcao para pegar a lista de ataques detectados dentro de um periodo especificado
def fn_analyser_tool(endTime,period,severitiesName):
    startTime = endTime - datetime.timedelta(days=int(period)) #Sets the initial time with the end time subtracted the period in days // Configura o tempo inicial com o tempo final subtraido do periodo em dias para analisar
    alertList = [] #List that will be populated with the attack log analysis // Lista que sera populada com a analise do attack log
    alertListLengh = 0
    totalAlertListLengh = 0
    triggeredAttacks = []
    print ('Initiating search on the attack log...')

    for severityName in severitiesName: #For loop to search in the attack log with all the severities desired // Laco for para consultar o attack log com todas as severidades desejadas
        count = 0
        alertListLengh = 0
        attackSearch = 'alerts?alertstate=any&timeperiod=custom&starttime=%s&endtime=%s&filter=attackSeverity:%s' % (startTime.strftime("%m/%d/%Y %H:%M"),endTime.strftime("%m/%d/%Y %H:%M"),severityName)
        attackLog = fn_get_request(attackSearch)
        alertList = fn_filter_alerts(attackLog ['alertsList'])
        alertListLengh += len(alertList)
        print ('Found approximately %s alerts of %s severity level...' % (attackLog ['totalAlertsCount'],severityName))
        count += 1
        triggeredAttacks = fn_triage_Attacks(alertList,startTime,endTime,triggeredAttacks,count)

        while attackLog ['totalAlertsCount'] > alertListLengh:
            nextPage = fn_get_request(attackSearch+'&page=next')
            alertList = fn_filter_alerts(nextPage ['alertsList'])
            alertListLengh += len(alertList)
            print ('%s alerts of %s severity level exported from attack log...' % (alertListLengh,severityName))
            print ()
            count += 1
            triggeredAttacks = fn_triage_Attacks(alertList,startTime,endTime,triggeredAttacks,count)
        totalAlertListLengh += alertListLengh

    print ('%s alerts found...' % str(totalAlertListLengh))
    return triggeredAttacks

# Function to set the severities that will be searched // Funcao para configurar as severidades que serao consultadas
def fn_get_severityNames():
    severitiesName = []
    while True:
        severity_selected = input ("Inform which severity level of attacks you wish to use in the blocking process (Informational, Low, Medium, High). When finished type 'Finish': ")
        if severity_selected in ['Informational','Low','Medium','High']:
            severitiesName.append(severity_selected)
        elif severity_selected == "Finish":
            break
        else:
            print ("Invalid option!")
    return severitiesName

def fn_get_severityIds(severitiesName):
    severityId = []
    IDs = {'Informational':[0],"Low":[1,2,3],"Medium":[4,5,6],"High":[7,8,9]}
    for name in severitiesName:
        for s_ID in IDs:
            if name == s_ID:
                severityId += IDs [s_ID]
    return severityId


print ()
print ("#############################################################################################################################")
print ("#  This is an application to automate the process of blocking attacks within a specified interface of McAfee NSP solution.  #")
print ("#  To guarantee that no benign traffic could be blocked it's highly recommended to exclude from the blocking process all    #")
print ("#  the attacks that were not analysed by your incident response team.                                                       #")
print ("#  If you still don't know which attacks already triggered in your environment are really malicious traffic                 #")
print ("#  and which ones are false-positives, run the Analyser builtin in this application to exclude all the triggered attacks    #")
print ("#  from the blocking process.                                                                                               #")
print ("#############################################################################################################################")
print ()
print ()

url = '%s/sdkapi/' %input("Insert the Manager's Address: ") #NSM Address // Endereco do NSM (Manager do IPS)
headers = {'Accept':'application/vnd.nsm.v2.0+json','Content-Type':'application/json','NSM-SDK-API':''} #Parameters that needs to be sent on the Header of the api request // Parametros necessarios no Header da requisicao
date = datetime.datetime.now().strftime("%Y-%m-%d--%H-%M-%S") #Get the current time // Pega o horario atual
user = input ("Username: ")
credencial_encoded = fn_base64encode(user,getpass.getpass ("Password: ")) #insert user and password and encodes it with function // Insercao de usuario e senha e encode com funcao
headers ['NSM-SDK-API'] = str(credencial_encoded,'utf-8') #Updates Header Parameters with the proper credentials // atualiza os Parametros do Header com as credenciais
authenticate = fn_get_request('session') #Make the request to authenticate the conection and get the session token // Faz a requisição para autenticar a conexao e pegar o token da sessao
logged_session = fn_base64encode(authenticate ['session'],authenticate ['userId']) #Encodes to base64 the session token and user id // Faz o encode em base64 do token de sessao e id do usuario
headers ['NSM-SDK-API'] = str(logged_session,'utf-8') #Updates Header Parameters with the proper session token // atualiza os Parametros do Header com o token da sessao
blockingOptions = ['DISABLE','ENABLE','ENABLE_SMART_BLOCKING'] #Possible options that an attack with response to block has // Possiveis opcoes que um ataque com possibilidade de bloquear pode ter
nonBlockingOptions = ['DISABLE','ENABLE_SMART_BLOCKING'] #Possible options different then full-blocking. Attacks with this option should been updated to enable block // Opções de ataque diferentes de bloqueio. ataques com essas opções serão atualizadaos para bloqueio
severitiesName = fn_get_severityNames() #Sets the severities that will be searched // Configura as severidades que serao consultadas
severityId = fn_get_severityIds(severitiesName) #Severities that will be considered to block // Severidades que serão consideradas para o bloqueio
endTime = datetime.datetime.now() #Sets the final time used to search in the attack log with the current time // Configura o tempo final de busca com o tempo atual


while True:
    confirmation = input('Do you wish to run the Analyser tool getting all alerts detected in your environment to get a list of triggered attacks? (Y/n)')
    if confirmation in ['','Y',"y"]:
        period = input('Type the period in days to have the attack logs analysed: ')
        triggeredAttacks = fn_analyser_tool(endTime,period,severitiesName)
        date = datetime.datetime.now() #Get the current time // Pega o horario atual
        f = open("triggered-attacks-list--%s--analyser-tool.txt" % date.strftime("%Y-%m-%d--%H-%M-%S"),"w")
        f.write (str(triggeredAttacks))
        f.close()
    elif confirmation in ["N","n"]:
        print ("In order to continue its necessary to inform a list of attacks to be excluded from the blocking attacks process. Blocking all the attacks could be seriously hazardous!")

        attacks = open(input("Type the name of the file with the triggered attacks list: ")).read()
        triggeredAttacks = str(attacks).split(",")
        date = datetime.datetime.now() #Get the current time // Pega o horario atual
        f = open("triggered-attacks-list--%s--manual-input.txt" % date.strftime("%Y-%m-%d--%H-%M-%S"),"w")
        f.write (str(triggeredAttacks))
        f.close()
        break
    else:
        print ("Invalid option!")



print ()
print ("Proceeding will start the process of \"shielding\" a policy...\n")
print ("All the attacks that matches the following criterias will be set to blocking mode:\n")
print ("---  The attack was NOT identified in the attack_log analysed according with the period selected (Found %s attacks that will be excluded from the process)...\n" % len(triggeredAttacks))
print ("---  The attack is classified with severities: %s...\n" % severitiesName)
print ("---  The attack\'s blocking properties are still set as: %s...\n" % nonBlockingOptions)
print ()
while True:
    confirmation = input("Do you wish to shield a policy based on the attack log analysed? (y/N)")
    if confirmation in ['y','Y']:
        fn_shield_policy()
    elif confirmation in ['n','N','']:
        print ("Aborting application...")
        break
    else:
        print ("Invalid option!")

fn_logoff_session()
