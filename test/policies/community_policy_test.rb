require 'test_helper'

class CommunityPolicyTest < ActiveSupport::TestCase

  test 'admin user should have proper authorization over communities' do
    current_user = users(:admin)
    community = Community.new

    assert CommunityPolicy.new(current_user, community).index?
    assert CommunityPolicy.new(current_user, community).create?
    assert CommunityPolicy.new(current_user, community).new?
    assert CommunityPolicy.new(current_user, community).show?
    assert CommunityPolicy.new(current_user, community).edit?
    assert CommunityPolicy.new(current_user, community).update?
    assert CommunityPolicy.new(current_user, community).destroy?
  end

  test 'general user should only be able to see index and show of communities' do
    current_user = users(:regular)
    community = Community.new

    assert CommunityPolicy.new(current_user, community).index?
    assert CommunityPolicy.new(current_user, community).show?

    assert_not CommunityPolicy.new(current_user, community).create?
    assert_not CommunityPolicy.new(current_user, community).new?
    assert_not CommunityPolicy.new(current_user, community).edit?
    assert_not CommunityPolicy.new(current_user, community).update?
    assert_not CommunityPolicy.new(current_user, community).destroy?
  end

  test 'anon user should only be able to see index and show of communities' do
    current_user = nil
    community = Community.new

    assert CommunityPolicy.new(current_user, community).index?
    assert CommunityPolicy.new(current_user, community).show?

    assert_not CommunityPolicy.new(current_user, community).create?
    assert_not CommunityPolicy.new(current_user, community).new?
    assert_not CommunityPolicy.new(current_user, community).edit?
    assert_not CommunityPolicy.new(current_user, community).update?
    assert_not CommunityPolicy.new(current_user, community).destroy?
  end

end
