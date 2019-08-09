class Collection < JupiterCore::LockedLdpObject

  has_solr_exporter Exporters::Solr::CollectionExporter

  include ObjectProperties

  ldp_object_includes Hydra::Works::CollectionBehavior

  # TODO: this should probably be renamed to share a name with member_of_paths on Item, so that their
  # facet results can be coalesced when Collections are mixed into search results along with Items, as in the
  # main search results
  has_attribute :community_id, ::TERMS[:ual].path
  has_attribute :description, ::RDF::Vocab::DC.description
  has_attribute :restricted, ::TERMS[:ual].restricted_collection
  has_multival_attribute :creators, ::RDF::Vocab::DC.creator

  def community
    Community.find(community_id)
  end

  def path
    "#{community_id}/#{id}"
  end

  def member_items
    Item.where(member_of_paths: path)
  end

  def member_theses
    Thesis.where(member_of_paths: path)
  end

  def member_objects
    member_items + member_theses
  end

  def as_json(_options)
    super(only: [:title, :id])
  end

  unlocked do
    before_destroy :can_be_destroyed?

    validates :community_id, presence: true
    validate :community_validations

    before_validation do
      self.visibility = JupiterCore::VISIBILITY_PUBLIC
    end

    before_save do
      if community_id_changed?
        # This adds the `pcdm::memberOf` predicate, pointing to the community
        self.member_of_collections = []
        # TODO: can this be streamlined so that a fetch from Fedora isn't needed?
        community.unlock_and_fetch_ldp_object do |unlocked_community|
          self.member_of_collections += [unlocked_community]
        end
      end
    end

    def can_be_destroyed?
      return true if member_objects.count == 0

      errors.add(:member_objects, :must_be_empty,
                 list_of_objects: member_objects.map(&:title).join(', '))
      throw(:abort)
    end

    def community_validations
      return unless community_id

      community = Community.find_by(id: community_id)
      errors.add(:community_id, :community_not_found, id: community_id) if community.blank?
    end
  end

end
