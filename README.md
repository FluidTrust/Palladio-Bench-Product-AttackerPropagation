# Palladio-Bench-Product-AttackPropagation

## Executing the product
We bundled a eclipse product, which can be used to start our analysis and view the models. It should be configured that it automatically opens a workspace with the necessary projects loaded.
*  [Download](https://updatesite.palladio-simulator.com/fluidtrust/palladio-bench-product-attackerpropagation/nightly/) and unzip the version for your operating system
    * **Attention:** The MAC-Version might not work, because of MACOS security features. In that case [this](https://sdqweb.ipd.kit.edu/wiki/PCM_Installation#Mac_OS_X) might help. If not, you can still use the update site or manually install the tooling, but you are required to solve the dependencies manually.
* Start the application by executing the *PalladioBench* binary (not the eclipse one!)
* After the load screen you should see 3 Projects in the Modelviewer on the left side:
    * edu.kit.ipd.sdq.kamp4attack.tests
    * org.palladiosimulator.pcm.confidentiality.context.analysis.testframework
    * org.palladiosimulator.pcm.confidentiality.context.analysis.testmodels
* The models are stored in *org.palladiosimulator.pcm.confidentiality.context.analysis.testmodels*.
    * By clicking on the arrow before the project you can see the content.
    * The evaluation models are stored in the following folders:
        * models/powerGrid
        * models/targetBreach
        * models/travelplanner
    * Each folder contains the pcm models (allocation, reposity, resourceenvironment, system, usagemodel), the attackermodel (*.attacker), the access control model (*.context) and eclipse launchconfig (*.launch)
        * with the launch config the scenario can be executed, by opening the context menu (normally right clock) and clicking "Run as"
    * for a description of the models see Model Description
* Additionally the accuracy tests can be executed automatically as Junit-Plugin-Test (only in the Linux binary):
    * Open edu.kit.ipd.sdq.kamp4attack.tests project
    * Navigate in the src folder to *edu.kit.ipd.sdq.kamp4attack.tests.casestudies* and *edu.kit.ipd.sdq.kamp4attack.tests.casestudies.travelplanner*.
    * By opening the context menu (right click usually) and "Run as" Junit-**Plugin**-Test
    * It is important to execute the tests as Plugin Tests since otherwise the dependencies can't be solved

## Model Descripton
* Target Breach
    * in folder targetBreach
* Ukrainian Power Grid
    * in folder powerGrid
* TravelPlanner
    * in folder travelplanner
    * Scenarios in folder *Attacker_Propagation_Accuracy*: 
         1. An Empty Attacker model. The analysis has no attacker, therefore no propagation should happen
         2. The attacker has no attack therefore only the initial component is affected
         3. The attacker has no specific attack but has some stolen credential. Therefore, only the credentials are allowed for the propagation
         4. Propagations based on vulnerabilites. The attacker has attacks for mainly one attack step. To verify that each propagation types work
            1. A Component to a Seff Propagation
            2. A Component to Component Propagtion
            3. The component compromises the resource it is deployed on
            4. The component compromises a remote resource (not the one it is deployed on)
            5. A linking Resource compromises a connected Resource container
            6. A linking Resource compromises a connected component
            7. A resource compromises a connected component
            8. A resource compromises another connected resource
        5. The attacker gains a new credential based on an attack, but can't take full control of the Linking Resource
        6. Tests whether the AttackVector option is considered in the analysis
        7.  Tests whether the Privilege option is considered in the analysis

    
