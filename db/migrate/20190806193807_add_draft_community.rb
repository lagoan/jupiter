class AddDraftCommunity < ActiveRecord::Migration[5.2]
  def change
    create_table :draft_communities do |t|
      t.uuid :community_id
      t.integer :visibility, default: 0, null: false
      t.references :owner, null: false, index: true, foreign_key: {to_table: :users, column: :id}
      t.date :record_created_at
      t.string :hydra_noid
      t.date :date_ingested
      t.string :title
      t.string :fedora3_uuid
      t.references :depositor, index: true, foreign_key: {to_table: :users, column: :id}
      t.text :description
      t.json :creators, array: true
      t.timestamps
    end
  end
end
