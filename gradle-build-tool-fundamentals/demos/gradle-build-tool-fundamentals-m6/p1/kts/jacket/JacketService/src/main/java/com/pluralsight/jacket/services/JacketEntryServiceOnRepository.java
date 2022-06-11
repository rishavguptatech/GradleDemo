package com.pluralsight.jacket.services;

import com.pluralsight.jacket.models.JacketEntry;
import com.pluralsight.repository.Repository;

import java.util.ArrayList;
import java.util.List;

public class JacketEntryServiceOnRepository implements JacketEntryService {
    private Repository repository;

    public JacketEntryServiceOnRepository(Repository jacketRepository) {
        this.repository = jacketRepository;
    }


    @Override
    public List<JacketEntry> getAllEntries() {
	return null;
    }
}

