![](https://github.com/QualiSystems/cloudshell-shells-documentaion-templates/blob/master/cloudshell_logo.png)

# **TeraVM Virtual 1G Shells**  

Release date: April 2018

Shell version: 1.0.0

Document version: 1.0

# In This Guide

* [Overview](#overview)
* [Downloading the Shell](#downloading-the-shell)
* [Importing and Configuring the Shell](#importing-and-configuring-the-shell)
* [Updating Python Dependencies for Shells](#updating-python-dependencies-for-shells)
* [Typical Workflows](#typical-workflows)
* [References](#references)
* [Release Notes](#release-notes)


# Overview
A shell integrates a device model, application or other technology with CloudShell. A shell consists of a data model that defines how the device and its properties are modeled in CloudShell, along with automation that enables interaction with the device via CloudShell.

### Traffic Generator Shells
CloudShell's traffic generator shells enable you to conduct traffic test activities on Devices Under Test (DUT) or Systems Under Test (SUT) from a sandbox. In CloudShell, a traffic generator is typically modeled using a chassis resource, which represents the traffic generator device and ports, and a controller service that runs the chassis commands, such as Load Configuration File, Start Traffic and Get Statistics. Chassis and controllers are modeled by different shells, allowing you to accurately model your real-life architecture. For example, scenarios where the chassis and controller are located on different machines.

For additional information on traffic generator shell architecture, and setting up and using a traffic generator in CloudShell, see the [Traffic Generators Overiew](http://help.quali.com/Online%20Help/9.0/Portal/Content/CSP/LAB-MNG/Trffc-Gens.htm?Highlight=traffic%20generator%20overview) online help topic.

### **TeraVM Virtual 1G Shells**
TeraVM virtual devices are modeled using several shells in CloudShell, providing you with connectivity and management capabilities such as device structure discovery and power management. 

For more information see the official **TeraVM** product documentation.

To model a TeraVM virtual device in CloudShell, use the following shells: 

▪ [CloudShell TeraVM Virtual vChassis Shell](https://community.quali.com/repos/3401/cloudshell-teravm-vchassis-shell-1), which provides connectivity and management capabilities, such as device structure discovery and power management for the TeraVM vChassis.

▪ [TeraVM Controller Shell (Service)](https://community.quali.com/repos/3287/teravm-controller-shell), which provides automation commands to run on the vChassis, such as Load Test Configuration, Start Traffic, Get Statistics.

▪ [CloudShell TeraVM vBlade Shell](https://community.quali.com/repos/3403/cloudshell-teravm-vblade-shell), which provides connectivity and management capabilities such as device structure discovery and power management for the CloudShell TeraVM vBlade.

### Standard version
The TeraVM Virtual 1G shells are based on the Traffic Shell Standard 1.0.0.

For detailed information about the shell’s structure and attributes, see the [Traffic Shell standard](https://github.com/QualiSystems/shell-traffic-standard/blob/master/spec/traffic_standard.md) in GitHub.

### Requirements

Release: **TeraVM Virtual Shells**

▪ TeraVM versions: 13.4 and above

▪ CloudShell version: 8.2 and above

### Data Model

The shell's data models include all shell metadata, families, and attributes.

#### **TeraVM vChassis Families and Models**

The families and models of the vChassis are listed in the following table:

|Family|Model|Description|
|:---|:---|:---|
|Virtual Traffic Generator Chassis|TeraVM Chassis|TeraVM Deployed Controller|
|Module|TeraVM Virtual Traffic Generator Module|TeraVM Deployed Module|
|Port|TeraVM Virtual Traffic Generator Port|Port on the Deployed TeraVM Module|

#### **TeraVM vChassis Attributes**

The attributes of the vChassis are listed in the following table:

|Attribute|Type|Description|
|:---|:---|:---|
|License Server|String|IP address or hostname of the License Server|
|Executive Server|String|IP address or hostname of the Executive Server|
|TVM Comms Network|String|TeraVM Comms Network name in vCenter|
|TVM MGMT Network|String|TeraVM Management Network name in vCenter|
|Password|Password|CLI password for the Deployed TeraVM Controller|
|User|String|CLI username for the Deployed TeraVM Controller|
|API Password|Password|API password for the Deployed TeraVM Controller|
|API User|String|API username for the Deployed TeraVM Controller|

#### **TeraVM Module Attributes (vBlade)**

The attributes of the vBlade are listed in the following table:

|Attribute|Type|Description|
|:---|:---|:---|
|TVM Comms Network|String|TeraVM Comms Network name in vCenter|
|TVM MGMT Network|String|TeraVM Management Network name in vCenter|

#### **TeraVM Port Attributes**

The attributes of the ports are listed in the following table:

|Attribute|Type|Description|
|:---|:---|:---|
|Logical Name|String|The port's logical name in the test configuration|
|Requested vNIC|String|vNIC number from vCenter|
|MAC Address|String|Port's MAC address|

### Automation
This section describes the automation (drivers) associated with the data model. The shell’s driver is provided as part of the shell package. There are two types of automation processes, Autoload and Resource. Autoload is executed when creating the resource in the **Inventory** dashboard, while resource commands are run in the sandbox.

For Traffic Generator shells, commands are configured and executed from the controller service in the sandbox, with the exception of the Autoload command, which is executed when creating the resource.

|Command|Description|
|:-----|:-----|
|Autoload|Creates the device structure, its hierarchy and attributes when deploying the App. The command can be rerun in the Inventory dashboard and not in the sandbox.|

#### TeraVM Controller Shell

|Command|Description|
|:-----|:-----|
|Load Configuration|Loads the configuration file and reserves necessary ports.<br>* **TeraVM config file** (String) (Mandatory): The configuration file name. <br>Path should include the protocol type, for example *tftp://10.10.10.10/asdf*.<br>* **Use ports from reservation** (Enum): Possible values: **True** or **False**. <br>Updates the configuration file with ports from the current reservation based on their **Logical Name** attributes.
|Start Traffic|Starts a test with the current configuration.|
|Stop Traffic|Stops running the test.|
|Get Results|Gets the test's result file and attaches it to the reservation.|

# Downloading the Shell
The TeraVM Virtual 1G shells are available from the [Quali Community Integrations](https://community.quali.com/integrations) page. 

Download the files into a temporary location on your local machine. 

The shells include:

|File name|Description|
|:---|:---|
|TeraVM_Controller_Shell_Package.zip|TeraVM Controller shell package|
|teravm-vchassis.zip|TeraVM vChassis shell package|
|teravm-vblade.zip|TeraVM vBlade shell package|
|teravm-offline-package-1.0.0.zip|Shell Python dependencies (for offline deployments only)|
|TeraVM.Sandbox.Setup.1.0.zip|CloudShell Reservation Setup script|

# Importing and Configuring the Shell
This section describes how to import the TeraVM Virtual shells and configure and modify the shell’s devices. 

### Importing the shells into CloudShell

**Note**: You will need to repeat these procedures, for the controller shell, the vChassis shell, and the vBlade shell.

**To import the shell into CloudShell:**
  1. Make sure you have the shell’s zip package. If not, download the shell from the [Quali Community's Integrations](https://community.quali.com/integrations) page.
  
  2. Backup your database.
  
  3. Log in to CloudShell Portal as administrator and access the relevant domain.
  
  4. In the user menu select **Import Package**.
  
     ![](https://github.com/QualiSystems/cloudshell-shells-documentaion-templates/blob/master/import_package.png)
     
  5. Browse to the location of the downloaded shell file, select the relevant *.zip* file and Click **Open**. Alternatively, drag the shell’s .zip file into CloudShell Portal.
  
  6. Import the rest of the shells by repeating steps 4 and 5.<br><br>The TeraVM Controller shell is displayed in the **App/Service>Applications** section of your blueprint, and can be used to run custom code and automation processes in the sandbox. For more information, see [Services Overview](http://help.quali.com/Online%20Help/9.0/Portal/Content/CSP/LAB-MNG/Services.htm?Highlight=services).<br><br>You can now use the vBlade and vChassis shells to create Apps that, once deployed in a sandbox, will spin up VMs that model a TeraVM traffic generator. See [Configuring a new App](#configuring-a-new-app). For more information, see [Apps Overview](http://help.quali.com/Online%20Help/9.0/Portal/Content/CSP/LAB-MNG/Apps.htm?Highlight=applications). 

### Offline installation of a shell

**Note:** Offline installation instructions are relevant only if CloudShell Execution Server has no access to PyPi. You can skip this section if your execution server has access to PyPi. For additional information, see the online help topic on offline dependencies.

In offline mode, import the shell into CloudShell and place any dependencies in the appropriate dependencies folder. The dependencies folder may differ, depending on the CloudShell version you are using:

* For CloudShell version 8.3 and above, see [Adding Shell and script packages to the local PyPi Server repository](#adding-shell-and-script-packages-to-the-local-pypi-server-repository).

* For CloudShell version 8.2, perform the appropriate procedure: [Adding Shell and script packages to the local PyPi Server repository](#adding-shell-and-script-packages-to-the-local-pypi-server-repository) or [Setting the python pythonOfflineRepositoryPath configuration key](#setting-the-python-pythonofflinerepositorypath-configuration-key).

### Adding shell and script packages to the local PyPi Server repository
If your Quali Server and/or execution servers work offline, you will need to copy all required Python packages, including the out-of-the-box ones, to the PyPi Server's repository on the Quali Server computer (by default *C:\Program Files (x86)\QualiSystems\CloudShell\Server\Config\Pypi Server Repository*).

For more information, see [Configuring CloudShell to Execute Python Commands in Offline Mode](http://help.quali.com/Online%20Help/9.0/Portal/Content/Admn/Cnfgr-Pyth-Env-Wrk-Offln.htm?Highlight=Configuring%20CloudShell%20to%20Execute%20Python%20Commands%20in%20Offline%20Mode).

**To add Python packages to the local PyPi Server repository:**
  1. If you haven't created and configured the local PyPi Server repository to work with the execution server, perform the steps in [Add Python packages to the local PyPi Server repository (offlinemode)](http://help.quali.com/Online%20Help/9.0/Portal/Content/Admn/Cnfgr-Pyth-Env-Wrk-Offln.htm?Highlight=offline%20dependencies#Add). 
  
  2. For each shell or script you add into CloudShell, do one of the following (from an online computer):
      * Connect to the Internet and download each dependency specified in the *requirements.txt* file with the following command: 
`pip download -r requirements.txt`. 
     The shell or script's requirements are downloaded as zip files.

      * In the [Quali Community's Integrations](https://community.quali.com/integrations) page, locate the shell and click the shell's **Download** link. In the page that is displayed, from the Downloads area, extract the dependencies package zip file.

3. Place these zip files in the local PyPi Server repository.
 
### Setting the python PythonOfflineRepositoryPath configuration key
Before PyPi Server was introduced as CloudShell’s python package management mechanism, the `PythonOfflineRepositoryPath` key was used to set the default offline package repository on the Quali Server machine, and could be used on specific Execution Server machines to set a different folder. 

**To set the offline python repository:**
1. Download the *teravm-offline-package-1.0.0* file, see [Downloading the Shell](#downloading-the-shell).

2. Unzip it to a local repository. Make sure the execution server has access to this folder. 

3.  On the Quali Server machine, in the *~\CloudShell\Server\customer.config* file, add the following key to specify the path to the default python package folder (for all Execution Servers):  
	`<add key="PythonOfflineRepositoryPath" value="repository 
full path"/>`

4. If you want to override the default folder for a specific Execution Server, on the Execution Server machine, in the *~TestShell\Execution Server\customer.config* file, add the following key:  
	`<add key="PythonOfflineRepositoryPath" value="repository 
full path"/>`

5. Restart the Execution Server.

### Configuring a new App

#### Configuring a new App based on the TeraVM vBlade shell

This section explains how to create an App template for the TeraVM vBlade shell (Module).

1. In CloudShell Portal, as Global administrator, open the **Manage – Apps** page.

2. Click **Add**.

3. Select **vCenter VM from Template**. <br>Note that CloudShell only supports vCenter as a Cloud Provider, however, you may use any of the available deployment options.

4. Enter the **Name** of the App and click **Create**.

5. In the **Deployment Paths** tab, select the **Cloud Provider** and enter the **vCenter Template** to be used in VM creation. It should include the full path and template name, for example *QualiFolder/Template*. 

	![](https://github.com/QualiSystems/cloudshell-tg-teravm-vblade/blob/master/teravm_module_app_deployment.png)

6. In the **App Resource** tab, select the **TeraVM Virtual Traffic Generator Module** shell and specify all required configuration attributes for this shell, see [TeraVM Module Attributes (vBlade)](#teravm-module-attributes-vblade).

	![](https://github.com/QualiSystems/cloudshell-tg-teravm-vblade/blob/master/teravm_module_app_resource.png)

7. Click **Done**.

#### Configuring a new App based on the TeraVM vChassis shell

This section explains how to create an App template for the TeraVM vChassis shell.

1. In CloudShell Portal, as Global administrator, open the **Manage – Apps** page.

2. Click **Add**.

3. Select **vCenter VM from Template**. <br>Note that CloudShell only supports vCenter as a Cloud Provider, however, you may use any of the available deployment options.

4. Enter the **Name** of the App and click **Create**.

5. In the **Deployment Paths** tab, select the **Cloud Provider** and enter the **vCenter Template** to be used in VM creation. It should include the full path and template name, for example *QualiFolder/Template*. 

	![](https://github.com/QualiSystems/cloudshell-tg-teravm-vblade/blob/master/teravm_chassis_app_deployment.png)

6. In the **App Resource** tab, select the **TeraVM vChassis** shell and specify all required configuration attributes for this shell, see [TeraVM vChassis Attributes](#teravm-vchassis-attributes).
	
	![](https://github.com/QualiSystems/cloudshell-tg-teravm-vblade/blob/master/teravm_chassis_app_resource.png)
	
7. Click **Done**.

### Configuring the TeraVM Controller 
This section explains how to configure the **TeraVM Controller** service, which enables end users to conduct traffic tests using the TeraVM traffic generator.

1. In your blueprint, add the **TeraVM Traffic Generator Controller** service. 
	1. Click **App/Service**.
	2. Select the **Traffic Generator Controller** category to view the list of controllers.

2. Click the plus sign next to the **TeraVM Traffic Generator Controller** to add the service into your diagram.

3. In the **Add Service** dialog box, specify the **Test Files Location** attribute with the location where test files should be downloaded. All other attributes aren't required and can be left blank.

	![](https://github.com/QualiSystems/cloudshell-tg-teravm-vblade/blob/master/teravm_controller_service.png)

3. Click **Add**.

### Configuring the setup script
This section explains how to add the setup script for the **TeraVM Virtual** shells.

**To add the setup script:**
1. Log in to CloudShell Portal as administrator of the relevant domain.

2. Go to the **Manage** dashboard and click **Scripts>Blueprint**.

3. Click **Add New Script**. 

4. From the list, select the downloaded setup script *TeraVM.Sandbox.Setup.1.0.zip*.

5. Click **Edit** and change the **Script Type** to **Setup**.

6. Click **Save**.


# Updating Python Dependencies for Shells
This section explains how to update your Python dependencies folder. This is required when you upgrade a shell that uses new/updated dependencies. It applies to both online and offline dependencies.

### Updating offline Python dependencies
**To update offline Python dependencies:**
1. Download the latest Python dependencies package zip file locally.

2. Extract the zip file to the suitable offline package folder(s). 

3. Terminate the shell’s instance, as explained [here](http://help.quali.com/Online%20Help/9.0/Portal/Content/CSP/MNG/Mng-Exctn-Srv-Exct.htm#Terminat). 

### Updating online Python dependencies
In online mode, the execution server automatically downloads and extracts the appropriate dependencies file to the online Python dependencies repository every time a new instance of the driver or script is created.

**To update online Python dependencies:**
* Terminate the shell’s instance, as explained [here](http://help.quali.com/Online%20Help/9.0/Portal/Content/CSP/MNG/Mng-Exctn-Srv-Exct.htm#Terminat). If an instance does not exist, the execution server will download the Python dependencies the next time a command of the driver or script runs.

# Typical Workflows 

**Workflow 1** - *Deploying the TeraVM Module and Controller* 
1. Create a new blueprint.
   1. Log in to CloudShell Portal and create a new blueprint (**Blueprint Catalog>Create Blueprint**).
   2. Give the blueprint a name.
   
2. Add Apps and Services to the blueprint. 
   1. Click **App/Services** from the toolbar.
   2. Add the following to the diagram:
   		* **TeraVM Traffic Generator Controller** service - see [Configuring the TeraVM Controller](#configuring-the-teravm-controller) for more information.
		* **TeraVM vChassis** App
		* **TeraVM vBlade** App
	
3. Update the blueprint setup script.
   1. Open the blueprint's properties, **Blueprint>Properties**. 
   2. In the **Scripts** section, remove the **Default Sandbox Setup 2.0** script by clicking the trash icon.
   3. Click **Add Script** and select **TeraVM.Sandbox.Setup.1.0** from the list. 
   4. Click **Update** to save changes.
   
4. In the blueprint workspace, click the **Reserve** button to deploy the **TeraVM Controller** and **TeraVM Module**. <br>You can now run your testing activity using the TeraVM traffic generator you spun up, as explained in the following workflow.

**Workflow 2** - *Running a test* 
1. Reserve a blueprint that is configured to run traffic tests, like the one configured in Workflow 1.

2. From the **TeraVM Traffic Generator Controller** service, run the **Load Configuration** command.
   1. Hover over the **TeraVM Traffic Generator Controller** service and click **Commands**.
   2. In the **Resource Commands** pane, click the **Load Configuration** command.
   3. Specify the **TeraVM config file** with the path of your test configuration file. <br>It can be a full path, or relative path under the location specified in the attribute **Test Files Location**, such as *<reservation_id>/test_name.bpt* or
only *test_name.bpt*. Make sure the path is accessible to the execution server running the command.
   4. Click **Run**, to load the test configuration to the **TeraVM Controller** and reserve necessary ports.
   
3. Run the **Start Test** command.

4. Run the **Stop Test** command.

5. Run the **Get Result** command.
    
   The test's result file is attached to the sandbox.


# References
To download and share integrations, see [Quali Community's Integrations](https://community.quali.com/integrations). 

For instructional training and documentation, see [Quali University](https://www.quali.com/university/).

To suggest an idea for the product, see [Quali's Idea box](https://community.quali.com/ideabox). 

To connect with Quali users and experts from around the world, ask questions and discuss issues, see [Quali's Community forums](https://community.quali.com/forums). 

# Release Notes 

### What's New

For release updates, see the shell's GitHub release pages as follows:

▪ [CloudShell TeraVM Virtual vChassis Shell release page](https://github.com/QualiSystems/cloudshell-tg-teravm-vchassis/releases)

▪ [TeraVM Controller Shell (Service) release page](https://github.com/QualiSystems/TeraVM-Controller-Shell/releases)

▪ [CloudShell TeraVM vBlade Shell release page](https://github.com/QualiSystems/cloudshell-tg-teravm-vblade/releases)
