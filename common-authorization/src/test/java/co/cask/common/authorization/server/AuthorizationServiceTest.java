/*
 * Copyright © 2014 Cask Data, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package co.cask.common.authorization.server;

import co.cask.common.authorization.AuthorizationContext;
import co.cask.common.authorization.DefaultAuthorizationContext;
import co.cask.common.authorization.ObjectId;
import co.cask.common.authorization.SubjectId;
import co.cask.common.authorization.UnauthorizedException;
import co.cask.common.authorization.client.AuthorizationClient;
import co.cask.common.authorization.guice.AuthorizationClientRuntimeModule;
import co.cask.common.authorization.guice.AuthorizationRuntimeModule;
import co.cask.common.authorization.guice.DiscoveryRuntimeModule;
import com.google.common.collect.ImmutableSet;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

/**
 * Test for {@link AuthorizationService}.
 */
public class AuthorizationServiceTest {

  private DefaultAuthorizationContext authorizationContext;
  private AuthorizationService authorizationService;
  private AuthorizationClient authorizationClient;

  @Before
  public void setUp() {
    authorizationContext = new DefaultAuthorizationContext();
    Injector injector = createInjector(authorizationContext);
    authorizationService = injector.getInstance(AuthorizationService.class);
    authorizationClient = injector.getInstance(AuthorizationClient.class);

    authorizationService.startAndWait();
  }

  @After
  public void tearDown() {
    authorizationService.stopAndWait();
  }

  @Test
  public void testAuthorized() throws IOException {
    SubjectId currentUser = SubjectId.ofUser("bob");
    ObjectId objectId = new ObjectId("STREAM", "someStream");

    authorizationClient.setACL(objectId, currentUser, "WRITE");
    authorizationClient.verifyAuthorized(objectId, ImmutableSet.of(currentUser), ImmutableSet.of("WRITE"));
  }

  @Test
  public void testCurrentUserAuthorized() throws IOException {
    SubjectId currentUser = SubjectId.ofUser("bob");
    authorizationContext.set(currentUser);
    ObjectId objectId = new ObjectId("STREAM", "someStream");

    authorizationClient.setACL(objectId, currentUser, "WRITE");
    authorizationClient.verifyCurrentUserAuthorized(objectId, ImmutableSet.of("WRITE"));
  }

  @Test
  public void testAuthorizedCache() throws IOException {
    SubjectId currentUser = SubjectId.ofUser("bob");
    ObjectId objectId = new ObjectId("STREAM", "someStream");

    authorizationClient.setACL(objectId, currentUser, "WRITE");
    authorizationClient.verifyAuthorized(objectId, ImmutableSet.of(currentUser), ImmutableSet.of("WRITE"));

    authorizationClient.deleteACL(objectId, currentUser, "WRITE");
    // Should get the cached result instead of the latest
    authorizationClient.verifyAuthorized(objectId, ImmutableSet.of(currentUser), ImmutableSet.of("WRITE"));

    authorizationClient.invalidateCache();
    try {
      // Should get the latest result now
      authorizationClient.verifyAuthorized(objectId, ImmutableSet.of(currentUser), ImmutableSet.of("WRITE"));
      Assert.fail("Expected UnauthorizedException");
    } catch (UnauthorizedException e) {
      // GOOD
    }
  }

  private Injector createInjector(final AuthorizationContext context) {
    return Guice.createInjector(
      new AbstractModule() {
        @Override
        protected void configure() {
          bind(AuthorizationContext.class).toInstance(context);
        }
      },
      new DiscoveryRuntimeModule().getInMemoryModules(),
      new AuthorizationRuntimeModule().getInMemoryModules(),
      new AuthorizationClientRuntimeModule().getInMemoryModules()
    );
  }
}
