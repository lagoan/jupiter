require 'test_helper'

class ProfileControllerTest < ActionDispatch::IntegrationTest

  setup do
    @item_collection = collections(:fantasy_books)
    @theses_collection = collections(:thesis)
    @admin = users(:admin)
    @user = users(:regular)
  end

  test 'should get profile index' do
    sign_in_as(@admin)
    get profile_url
    assert_response :success
  end

  test 'should view draft item in profile' do
    sign_in_as(@user)

    draft_item = draft_items(:inactive)

    patch item_draft_url(id: :describe_item, item_id: draft_item.id), params: {
      draft_item: {
        title: 'Random Book',
        type_id: types(:book).id,
        language_ids: [languages(:english).id],
        creators: ['Jane Doe', 'Bob Smith'],
        subjects: ['Best Seller', 'Adventure'],
        date_created: Date.current,
        description: 'Really random description about this random book',
        community_id: [@item_collection.community_id],
        collection_id: [@item_collection.id]
      }
    }

    get profile_url
    assert_includes @response.body, 'Random Book'
  end

  test 'should view draft thesis in profile' do
    sign_in_as(@admin)

    draft_thesis = draft_theses(:inactive)
    patch admin_thesis_draft_url(id: :describe_thesis, thesis_id: draft_thesis.id), params: {
      draft_thesis: {
        title: 'Random Thesis',
        creator: 'Jane Doe',
        graduation_year: 2018,
        graduation_term: '06',
        description: 'Really random description about this random thesis',
        community_id: [@theses_collection.community_id],
        collection_id: [@theses_collection.id]
      }
    }

    get profile_url
    assert_includes @response.body, 'Random Thesis'
  end

end
