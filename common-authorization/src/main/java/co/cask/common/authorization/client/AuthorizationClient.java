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
package co.cask.common.authorization.client;

import co.cask.common.authorization.ACLEntry;
import co.cask.common.authorization.AuthorizationContext;
import co.cask.common.authorization.ObjectId;
import co.cask.common.authorization.SubjectId;
import co.cask.common.authorization.UnauthorizedException;
import co.cask.common.authorization.guice.BaseURISupplier;
import co.cask.common.http.HttpRequest;
import co.cask.common.http.HttpRequests;
import co.cask.common.http.HttpResponse;
import co.cask.common.http.ObjectResponse;
import com.google.common.base.Objects;
import com.google.common.base.Supplier;
import com.google.common.base.Throwables;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import com.google.common.reflect.TypeToken;
import com.google.gson.Gson;
import com.google.inject.Inject;
import com.google.inject.name.Named;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * Provides ways to verify, create, and list ACL entries.
 */
public class AuthorizationClient {

  public static final String NAME = "AuthorizationClient";

  private static final long DEFAULT_CACHE_EXPIRE_AFTER_ACCESS_MIN = 5;
  private static final long DEFAULT_CACHE_MAX_SIZE = 10000;

  private static final Gson GSON = new Gson();
  private final AuthorizationContext context;

  private final LoadingCache<Key, List<ACLEntry>> aclCache;
  private final Supplier<URI> baseURISupplier;

  @Inject
  public AuthorizationClient(AuthorizationContext context, @Named(NAME) BaseURISupplier baseURISupplier) {
    this.context = context;
    this.baseURISupplier = baseURISupplier;
    this.aclCache = CacheBuilder.newBuilder()
      .maximumSize(DEFAULT_CACHE_MAX_SIZE)
      .expireAfterAccess(DEFAULT_CACHE_EXPIRE_AFTER_ACCESS_MIN, TimeUnit.MINUTES)
      .build(new CacheLoader<Key, List<ACLEntry>>() {
        @Override
        public List<ACLEntry> load(Key key) throws Exception {
          ObjectId objectId = key.getObjectId();
          SubjectId subjectId = key.getSubjectId();

          String path = String.format("/v1/acls/%s/%s/%s/%s", objectId.getType(), objectId.getId(),
                                      subjectId.getType(), subjectId.getId());
          HttpRequest request = HttpRequest.get(resolveURL(path)).build();
          HttpResponse response = HttpRequests.execute(request);
          return ObjectResponse.fromJsonBody(response, new TypeToken<List<ACLEntry>>() { }).getResponseObject();
        }
      });
  }

  /**
   * @param objectId the object that is being accessed
   * @param subjectIds the subjects that are accessing the objectId
   * @param requiredPermissions the permissions that are required for access
   * @return true if one of the subjectIds has all of the requiredPermissions to access the objectId
   * @throws IOException if an error occurred when contacting the authorization service
   */
  public boolean isAuthorized(ObjectId objectId, Iterable<SubjectId> subjectIds,
                              Iterable<String> requiredPermissions) throws IOException {
    for (SubjectId subjectId : subjectIds) {
      List<ACLEntry> acls = this.getACLs(objectId, subjectId);
      if (fulfillsRequiredPermissions(acls, requiredPermissions)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Throws {@link UnauthorizedException} if none of the subjectIds are authorized to access the objectId
   * for all of the requiredPermissions.
   *
   * @param objectId the object that is being accessed
   * @param subjectIds the subjects that are accessing the objectId
   * @param requiredPermissions the permissions that are required for access
   * @throws IOException if an error occurred when contacting the authorization service
   */
  public void verifyAuthorized(ObjectId objectId, Iterable<SubjectId> subjectIds,
                               Iterable<String> requiredPermissions) throws IOException {
    if (!isAuthorized(objectId, subjectIds, requiredPermissions)) {
      throw new UnauthorizedException();
    }
  }

  /**
   * Throws {@link UnauthorizedException} if the subjectId is not authorized to access the objectId
   * for all of the requiredPermissions.
   *
   * @param objectId the object that is being accessed
   * @param subjectId the subject that is accessing the objectId
   * @param requiredPermissions the permissions that are required for access
   * @throws IOException if an error occurred when contacting the authorization service
   */
  public void verifyAuthorized(ObjectId objectId, SubjectId subjectId,
                               Iterable<String> requiredPermissions) throws IOException {
    if (!isAuthorized(objectId, ImmutableSet.of(subjectId), requiredPermissions)) {
      throw new UnauthorizedException();
    }
  }

  /**
   * @param objectId the object that is being accessed
   * @param requiredPermissions the permissions that are required for access
   * @return true if the current user or its groups have all of the requiredPermissions to access the objectId
   * @throws IOException if an error occurred when contacting the authorization service
   */
  public boolean isCurrentUserAuthorized(ObjectId objectId, Iterable<String> requiredPermissions) throws IOException {
    return isAuthorized(objectId, ImmutableSet.of(context.getCurrentUser()), requiredPermissions) ||
      isAuthorized(objectId, context.getCurrentUsersGroups(), requiredPermissions);
  }

  /**
   * Throws {@link UnauthorizedException} if the current user or its groups are not authorized to access the objectId
   * for all of the requiredPermissions.
   *
   * @param objectId the object that is being accessed
   * @param requiredPermissions the permissions that are required for access
   * @throws IOException if an error occurred when contacting the authorization service
   */
  public void verifyCurrentUserAuthorized(ObjectId objectId, Iterable<String> requiredPermissions) throws IOException {
    if (!isCurrentUserAuthorized(objectId, requiredPermissions)) {
      throw new UnauthorizedException();
    }
  }

  /**
   * @param objectId the object that is being accessed
   * @param subjectId the subject that is accessing the objectId
   * @return the list of the {@link ACLEntry}s that are relevant to an object and a subject
   * @throws IOException if an error occurred when contacting the authorization service
   */
  public List<ACLEntry> getACLs(ObjectId objectId, SubjectId subjectId) throws IOException {
    try {
      return aclCache.get(new Key(objectId, subjectId));
    } catch (ExecutionException e) {
      Throwables.propagateIfPossible(e.getCause(), IOException.class);
      throw Throwables.propagate(e.getCause());
    }
  }

  /**
   * Sets an {@link ACLEntry} for an object, subject, and a permission. This allows the subject to
   * access the object for the specified permission.
   *
   * <p>
   * For example, if object is "secretFile", subject is "Bob", and permission is "WRITE", then "Bob"
   * would be allowed to write to the "secretFile", assuming that what is doing the writing is protecting
   * the "secretFile" via a call to one of the {@code verifyAuthorized()} or {@code isAuthorized()} calls.
   * </p>
   *
   * @param objectId the object that is being accessed
   * @param subjectId the subject that is accessing the objectId
   * @param permission the permission to allow the subject to operate on the object for
   * @return true if the {@link ACLEntry} did not previously exist
   * @throws IOException if an error occurred when contacting the authorization service
   */
  public boolean setACL(ObjectId objectId, SubjectId subjectId, String permission) throws IOException {
    String path = String.format("/v1/acls/%s/%s/%s/%s/%s", objectId.getType(), objectId.getId(),
                                subjectId.getType(), subjectId.getId(), permission);
    HttpRequest request = HttpRequest.post(resolveURL(path))
      .withBody(GSON.toJson(new ACLEntry(objectId, subjectId, permission)))
      .build();

    HttpResponse response = HttpRequests.execute(request);
    if (response.getResponseCode() == HttpURLConnection.HTTP_OK) {
      return true;
    } else if (response.getResponseCode() == HttpURLConnection.HTTP_NOT_MODIFIED) {
      return false;
    }

    throw new IOException("Unexpected response: " + response.getResponseCode() + ": " + response.getResponseMessage());
  }

  /**
   * Deletes an {@link ACLEntry} for an object, subject, and a permission. This disallows the subject to
   * access the object for the specified permission.
   *
   * <p>
   * For example, if object is "secretFile", subject is "Bob", and permission is "WRITE", then "Bob"
   * would be no longer allowed to write to the "secretFile", assuming that what is doing the writing is protecting
   * the "secretFile" via a call to one of the {@code verifyAuthorized()} or {@code isAuthorized()} calls.
   * </p>
   *
   * @param objectId the object that is being accessed
   * @param subjectId the subject that is accessing the objectId
   * @param permission the permission to disallow the subject to operate on the object for
   * @return true if the {@link ACLEntry} previously existed
   * @throws IOException if an error occurred when contacting the authorization service
   */
  public boolean deleteACL(ObjectId objectId, SubjectId subjectId, String permission) throws IOException {
    String path = String.format("/v1/acls/%s/%s/%s/%s/%s", objectId.getType(), objectId.getId(),
                                subjectId.getType(), subjectId.getId(), permission);
    HttpRequest request = HttpRequest.delete(resolveURL(path)).build();

    HttpResponse response = HttpRequests.execute(request);
    if (response.getResponseCode() == HttpURLConnection.HTTP_OK) {
      return true;
    } else if (response.getResponseCode() == HttpURLConnection.HTTP_NOT_MODIFIED) {
      return false;
    }

    throw new IOException("Unexpected response: " + response.getResponseCode() + ": " + response.getResponseMessage());
  }

  public void invalidateCache() {
    aclCache.invalidateAll();
  }

  protected URL resolveURL(String path) throws MalformedURLException {
    return baseURISupplier.get().resolve(path).toURL();
  }

  private boolean fulfillsRequiredPermissions(List<ACLEntry> aclEntries, Iterable<String> requiredPermissions) {
    Set<String> remainingRequiredPermission = Sets.newHashSet(requiredPermissions);
    for (ACLEntry aclEntry : aclEntries) {
      remainingRequiredPermission.remove(aclEntry.getPermission());
    }
    return remainingRequiredPermission.isEmpty();
  }

  /**
   * Key for {@link #aclCache}: (ObjectId, SubjectId)
   */
  private static final class Key {
    private final ObjectId objectId;
    private final SubjectId subjectId;

    private Key(ObjectId objectId, SubjectId subjectId) {
      this.objectId = objectId;
      this.subjectId = subjectId;
    }

    public ObjectId getObjectId() {
      return objectId;
    }

    public SubjectId getSubjectId() {
      return subjectId;
    }

    @Override
    public int hashCode() {
      return Objects.hashCode(objectId, subjectId);
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }
      if (obj == null || getClass() != obj.getClass()) {
        return false;
      }
      final Key other = (Key) obj;
      return Objects.equal(this.objectId, other.objectId) && Objects.equal(this.subjectId, other.subjectId);
    }
  }
}
