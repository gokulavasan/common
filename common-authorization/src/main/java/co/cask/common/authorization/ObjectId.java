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
package co.cask.common.authorization;

import com.google.common.base.Objects;
import com.google.common.base.Preconditions;

/**
 * Uniquely identifies an object, as defined in {@link ACLStore}.
 */
public class ObjectId {

  private final String type;
  private final String id;

  public ObjectId(String type, String id) {
    Preconditions.checkArgument(type != null, "type must be provided");
    Preconditions.checkArgument(id != null, "id must be provided");
    this.type = type;
    this.id = id;
  }

  public String getType() {
    return type;
  }

  public String getId() {
    return id;
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(type, id);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null || getClass() != obj.getClass()) {
      return false;
    }
    final ObjectId other = (ObjectId) obj;
    return Objects.equal(this.type, other.type) && Objects.equal(this.id, other.id);
  }

  @Override
  public String toString() {
    return Objects.toStringHelper(this).add("type", type).add("id", id).toString();
  }
}
