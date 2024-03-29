package edu.kit.ipd.sdq.kamp4attack.tests.change.credentials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;

import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.LinkingPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;
import edu.kit.ipd.sdq.kamp4attack.tests.change.AbstractChangeTests;

class PropagationContextLinkingResourceTest extends AbstractChangeTests {
    private void createPolicies(final UsageSpecification contextSet) {
        this.createPolicyEntity(contextSet, this.environment.getResourceContainer_ResourceEnvironment()
            .get(0));
        this.createPolicyEntity(contextSet, this.environment.getResourceContainer_ResourceEnvironment()
            .get(1));
        this.createPolicyEntity(contextSet, this.environment.getResourceContainer_ResourceEnvironment()
            .get(2));

    }

    private void isNoAssemblyResourceChange(final CredentialChange change) {
        assertTrue(change.getCompromisedassembly()
            .isEmpty());
        assertTrue(change.getCompromisedresource()
            .isEmpty());
    }

    private void isNoContextChangeNoAssemblyNoResource(final CredentialChange change) {
        assertTrue(change.getContextchange()
            .isEmpty());
        this.isNoAssemblyResourceChange(change);
    }

    private void runContextLinkingToResourcePropagation(final CredentialChange change) {
        this.generateXML();
        final var contextChange = new LinkingPropagationContext(this.getBlackboardWrapper(), change);
        contextChange.calculateLinkingResourceToResourcePropagation();
    }

    @Test
    void testContextLinkingToResourcePropagation() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = this.createContext("Test");
        this.createContextChange(context, change);

        final var linkingChange = this.createLinkingChange(change);
        final var linkingResource = linkingChange.getAffectedElement();

        this.createPolicies(context);

        this.runContextLinkingToResourcePropagation(change);

        assertTrue(change.getCompromisedassembly()
            .isEmpty());
        assertEquals(3, change.getCompromisedresource()
            .size());
        assertTrue(change.getCompromisedresource()
            .stream()
            .anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                    this.environment.getResourceContainer_ResourceEnvironment()
                        .get(0))));
        assertTrue(change.getCompromisedresource()
            .stream()
            .anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                    this.environment.getResourceContainer_ResourceEnvironment()
                        .get(1))));
        assertTrue(change.getCompromisedresource()
            .stream()
            .anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                    this.environment.getResourceContainer_ResourceEnvironment()
                        .get(2))));
        assertEquals(1, change.getContextchange()
            .size());
        assertTrue(EcoreUtil.equals(change.getContextchange()
            .get(0)
            .getAffectedElement(), context));
        assertEquals(1, change.getCompromisedlinkingresource()
            .size());
        assertTrue(EcoreUtil.equals(change.getCompromisedlinkingresource()
            .get(0)
            .getAffectedElement(), linkingResource));
        assertTrue(change.isChanged());

    }

    void testContextLinkingToResourcePropagationDuplicate() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = this.createContext("Test");
        this.createContextChange(context, change);

        final var linkingChange = this.createLinkingChange(change);
        final var linkingResource = linkingChange.getAffectedElement();

        this.createResourceChange(change, this.environment.getResourceContainer_ResourceEnvironment()
            .get(0));
        this.createResourceChange(change, this.environment.getResourceContainer_ResourceEnvironment()
            .get(1));
        this.createResourceChange(change, this.environment.getResourceContainer_ResourceEnvironment()
            .get(2));

        this.createPolicies(context);

        this.runContextLinkingToResourcePropagation(change);

        assertTrue(change.getCompromisedassembly()
            .isEmpty());
        assertEquals(3, change.getCompromisedresource()
            .size());
        assertTrue(change.getCompromisedresource()
            .stream()
            .anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                    this.environment.getResourceContainer_ResourceEnvironment()
                        .get(0))));
        assertTrue(change.getCompromisedresource()
            .stream()
            .anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                    this.environment.getResourceContainer_ResourceEnvironment()
                        .get(1))));
        assertTrue(change.getCompromisedresource()
            .stream()
            .anyMatch(e -> EcoreUtil.equals(e.getAffectedElement(),
                    this.environment.getResourceContainer_ResourceEnvironment()
                        .get(2))));
        assertEquals(1, change.getContextchange()
            .size());
        assertTrue(EcoreUtil.equals(change.getContextchange()
            .get(0)
            .getAffectedElement(), context));
        assertEquals(1, change.getCompromisedlinkingresource()
            .size());
        assertTrue(EcoreUtil.equals(change.getCompromisedlinkingresource()
            .get(0)
            .getAffectedElement(), linkingResource));
        assertFalse(change.isChanged());

    }

    @Test
    void testContextLinkingToResourcePropagationNoContextNoStartResource() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        this.runContextLinkingToResourcePropagation(change);

        this.isNoContextChangeNoAssemblyNoResource(change);
        assertTrue(change.getCompromisedlinkingresource()
            .isEmpty());
        assertFalse(change.isChanged());

    }

    @Test
    void testContextLinkingToResourcePropagationNoOwnedContext() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = this.createContext("Test");

        final var linkingChange = this.createLinkingChange(change);
        final var linkingResource = linkingChange.getAffectedElement();

        this.createPolicies(context);

        this.runContextLinkingToResourcePropagation(change);

        this.isNoContextChangeNoAssemblyNoResource(change);
        assertEquals(1, change.getCompromisedlinkingresource()
            .size());
        assertTrue(EcoreUtil.equals(change.getCompromisedlinkingresource()
            .get(0)
            .getAffectedElement(), linkingResource));
        assertFalse(change.isChanged());

    }

    @Test
    void testContextLinkingToResourcePropagationNoOwnedContextNoStartResource() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = this.createContext("Test");
        this.createPolicies(context);

        this.runContextLinkingToResourcePropagation(change);

        this.isNoContextChangeNoAssemblyNoResource(change);
        assertTrue(change.getCompromisedlinkingresource()
            .isEmpty());
        assertFalse(change.isChanged());

    }

    @Test
    void testContextLinkingToResourcePropagationWrongContext() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var contextOwned = this.createContext("Owned");
        this.createContextChange(contextOwned, change);

        final var context = this.createContext("Test");

        final var linkingChange = this.createLinkingChange(change);
        final var linkingResource = linkingChange.getAffectedElement();

        this.createPolicies(context);

        this.runContextLinkingToResourcePropagation(change);

        this.isNoAssemblyResourceChange(change);
        assertEquals(1, change.getContextchange()
            .size());
        assertTrue(EcoreUtil.equals(change.getContextchange()
            .get(0)
            .getAffectedElement(), contextOwned));
        assertEquals(1, change.getCompromisedlinkingresource()
            .size());
        assertTrue(EcoreUtil.equals(change.getCompromisedlinkingresource()
            .get(0)
            .getAffectedElement(), linkingResource));
        assertFalse(change.isChanged());

    }

    void testContextLinkingToResourcePropagationWrongStartPoint() {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();

        final var context = this.createContext("Test");

        this.createContextChange(context, change);

        final var linkingChange = this.createLinkingChange(change,
                this.environment.getLinkingResources__ResourceEnvironment()
                    .get(1));
        final var linkingResource = linkingChange.getAffectedElement();

        this.createPolicyEntity(context, this.environment.getResourceContainer_ResourceEnvironment()
            .get(0));

        this.runContextLinkingToResourcePropagation(change);

        this.isNoAssemblyResourceChange(change);
        assertEquals(1, change.getContextchange()
            .size());
        assertTrue(EcoreUtil.equals(change.getContextchange()
            .get(0)
            .getAffectedElement(), context));
        assertEquals(1, change.getCompromisedlinkingresource()
            .size());
        assertTrue(EcoreUtil.equals(change.getCompromisedlinkingresource()
            .get(0)
            .getAffectedElement(), linkingResource));
        assertFalse(change.isChanged());

    }

}
