package edu.kit.ipd.sdq.kamp4attack.tests.change.credentials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.ResourceContainerPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;
import edu.kit.ipd.sdq.kamp4attack.tests.change.AbstractChangeTests;

class PropagationResourceTest extends AbstractChangeTests {

    private void isNoAssemblyResourceLinkingPropagation(final CredentialChange change,
            final ResourceContainer resource) {
        this.isNoResourceLinkingPropagation(change, resource);
        assertTrue(change.getCompromisedassembly()
            .isEmpty());

    }

    private void isNoResourceLinkingPropagation(final CredentialChange change, final ResourceContainer resource) {
        assertTrue(change.getCompromisedlinkingresource()
            .isEmpty());
        assertEquals(1, change.getCompromisedresource()
            .size());
        assertTrue(EcoreUtil.equals(change.getCompromisedresource()
            .get(0)
            .getAffectedElement(), resource));
    }

    private void runResourceAssemblyPropagation(final CredentialChange change) {
        this.generateXML();
        final var wrapper = this.getBlackboardWrapper();
        final var resourceChange = new ResourceContainerPropagationContext(wrapper, change);
        resourceChange.calculateResourceContainerToLocalAssemblyContextPropagation();
    }

    private void runResourceContextPropagation(final CredentialChange change) {
        this.generateXML();
        final var wrapper = this.getBlackboardWrapper();
        final var resourceChange = new ResourceContainerPropagationContext(wrapper, change);
        resourceChange.calculateResourceContainerToContextPropagation();
    }

    @Test
    void testResourceToAssemblyPropagation() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var resourceChange = this.createResourceChange(change);
        final var resource = resourceChange.getAffectedElement();

        final var context = this.createContext("Test");

        this.createPolicyEntity(context, this.assembly.getAssemblyContexts__ComposedStructure()
            .get(0));

        this.runResourceAssemblyPropagation(change);

        this.isNoResourceLinkingPropagation(change, resource);
        assertTrue(change.getContextchange()
            .isEmpty());
        assertEquals(1, change.getCompromisedassembly()
            .size());
        assertTrue(EcoreUtil.equals(change.getCompromisedassembly()
            .get(0)
            .getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure()
                    .get(0)));
        assertTrue(change.isChanged());
    }

    @Test
    void testResourceToAssemblyPropagationKeepContextChange() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var resourceChange = this.createResourceChange(change);
        final var resource = resourceChange.getAffectedElement();

        final var context = this.createContext("Test");
        final var contextChange = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        contextChange.setAffectedElement(context);
        change.getContextchange()
            .add(contextChange);

        this.createPolicyEntity(context, this.assembly.getAssemblyContexts__ComposedStructure()
            .get(0));
        this.createAttributeProvider(context, this.assembly.getAssemblyContexts__ComposedStructure()
            .get(0));

        this.runResourceAssemblyPropagation(change);

        this.isNoResourceLinkingPropagation(change, resource);
        assertEquals(1, change.getContextchange()
            .size());
        assertTrue(EcoreUtil.equals(change.getContextchange()
            .get(0)
            .getAffectedElement(), context));
        assertEquals(1, change.getCompromisedassembly()
            .size());
        assertTrue(EcoreUtil.equals(change.getCompromisedassembly()
            .get(0)
            .getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure()
                    .get(0)));
        assertTrue(change.isChanged());
    }

    @Test
    void testResourceToAssemblyPropagationNoContextChangeProvider() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var resourceChange = this.createResourceChange(change);
        final var resource = resourceChange.getAffectedElement();

        final var context = this.createContext("Test");

        this.createPolicyEntity(context, this.assembly.getAssemblyContexts__ComposedStructure()
            .get(0));
        this.createAttributeProvider(context, this.assembly.getAssemblyContexts__ComposedStructure()
            .get(0));

        this.runResourceAssemblyPropagation(change);

        this.isNoResourceLinkingPropagation(change, resource);
        assertTrue(change.getContextchange()
            .isEmpty());
        assertEquals(1, change.getCompromisedassembly()
            .size());
        assertTrue(EcoreUtil.equals(change.getCompromisedassembly()
            .get(0)
            .getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure()
                    .get(0)));
        assertTrue(change.isChanged());
    }

    @Test
    void testResourceToAssemblyPropagationNoSpecification() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var resourceChange = this.createResourceChange(change);
        final var resource = resourceChange.getAffectedElement();
        this.runResourceAssemblyPropagation(change);

        this.isNoResourceLinkingPropagation(change, resource);
        assertTrue(change.getContextchange()
            .isEmpty());
        assertEquals(1, change.getCompromisedassembly()
            .size());
        assertTrue(EcoreUtil.equals(change.getCompromisedassembly()
            .get(0)
            .getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure()
                    .get(0)));
        assertTrue(change.isChanged());
    }

    @Test
    void testResourceToAssemblyPropagationSkipDuplicates() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var resourceChange = this.createResourceChange(change);
        final var resource = resourceChange.getAffectedElement();

        final var assemblyChange = KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedAssembly();
        assemblyChange.setAffectedElement(this.assembly.getAssemblyContexts__ComposedStructure()
            .get(0));
        change.getCompromisedassembly()
            .add(assemblyChange);

        this.runResourceAssemblyPropagation(change);
        this.isNoResourceLinkingPropagation(change, resource);
        assertTrue(change.getContextchange()
            .isEmpty());
        assertEquals(1, change.getCompromisedassembly()
            .size());
        assertTrue(EcoreUtil.equals(change.getCompromisedassembly()
            .get(0)
            .getAffectedElement(),
                this.assembly.getAssemblyContexts__ComposedStructure()
                    .get(0)));
        assertFalse(change.isChanged());
    }

    @Test
    void testResourceToContextPropagation() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var resourceChange = this.createResourceChange(change);
        final var resource = resourceChange.getAffectedElement();

        final var context = this.createContext("Test");
        this.createAttributeProvider(context, resource);

        this.runResourceContextPropagation(change);

        this.isNoAssemblyResourceLinkingPropagation(change, resource);
        assertEquals(1, change.getContextchange()
            .size());
        assertTrue(EcoreUtil.equals(context, change.getContextchange()
            .get(0)
            .getAffectedElement()));
        assertTrue(change.isChanged());
    }

    @Test
    void testResourceToContextPropagationKeep() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var resourceChange = this.createResourceChange(change);
        final var resource = resourceChange.getAffectedElement();

        final var contextOriginal = this.createContext("Own");
        final var contextChange = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        contextChange.setAffectedElement(contextOriginal);
        change.getContextchange()
            .add(contextChange);
        final var context = this.createContext("Test");
        this.createAttributeProvider(context, resource);

        this.runResourceContextPropagation(change);

        this.isNoAssemblyResourceLinkingPropagation(change, resource);
        assertEquals(2, change.getContextchange()
            .size());
        assertTrue(change.getContextchange()
            .stream()
            .anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(), contextOriginal)));
        assertTrue(change.getContextchange()
            .stream()
            .anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(), context)));
        assertTrue(change.isChanged());
    }

    @Test
    void testResourceToContextPropagationNoContextsNoSpecification() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var resourceChange = this.createResourceChange(change);
        final var resource = resourceChange.getAffectedElement();

        this.runResourceContextPropagation(change);

        this.isNoAssemblyResourceLinkingPropagation(change, resource);
        assertTrue(change.getContextchange()
            .isEmpty());
        assertFalse(change.isChanged());
    }

    @Test
    void testResourceToContextPropagationNoSpecification() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var resourceChange = this.createResourceChange(change);
        final var resource = resourceChange.getAffectedElement();

        this.createContext("Test");
        this.runResourceContextPropagation(change);

        this.isNoAssemblyResourceLinkingPropagation(change, resource);
        assertTrue(change.getContextchange()
            .isEmpty());
        assertFalse(change.isChanged());
    }

    @Test
    void testResourceToContextPropagationSkipDuplicate() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var resourceChange = this.createResourceChange(change);
        final var resource = resourceChange.getAffectedElement();

        final var context = this.createContext("Own");
        final var contextChange = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        contextChange.setAffectedElement(context);
        change.getContextchange()
            .add(contextChange);
        this.createAttributeProvider(context, resource);

        this.runResourceContextPropagation(change);

        this.isNoAssemblyResourceLinkingPropagation(change, resource);
        assertEquals(1, change.getContextchange()
            .size());
        assertTrue(EcoreUtil.equals(context, change.getContextchange()
            .get(0)
            .getAffectedElement()));
        assertFalse(change.isChanged());
    }

    @Test
    void testResourceToContextPropagationWrongSpecification() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var resourceChange = this.createResourceChange(change);
        final var resource = resourceChange.getAffectedElement();

        final var context = this.createContext("Test");
        this.createAttributeProvider(context, this.environment.getResourceContainer_ResourceEnvironment()
            .get(1));

        this.runResourceContextPropagation(change);

        this.isNoAssemblyResourceLinkingPropagation(change, resource);
        assertTrue(change.getContextchange()
            .isEmpty());
        assertFalse(change.isChanged());
    }

}
