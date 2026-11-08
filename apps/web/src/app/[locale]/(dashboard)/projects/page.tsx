"use client";

import { useTranslations } from "next-intl";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, APIError, Project } from "@/lib/api";
import { LoadError } from "@/components/ui/load-error";
import { queryKeys } from "@/lib/query/keys";
import { Plus, Trash2, Upload, FolderOpen } from "lucide-react";
import Link from "next/link";

export default function ProjectsPage() {
  const t = useTranslations("Projects");
  const tc = useTranslations("Common");
  const queryClient = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);

  const projectsQuery = useQuery({
    queryKey: queryKeys.projects.list(),
    queryFn: async () => {
      try {
        return (await api.projects.list()) || [];
      } catch (error) {
        // M65 bug 10: a failed load used to resolve to [] and render the
        // "No projects yet" empty state. It is now an error (with retry).
        console.error("Failed to load projects:", error);
        throw error;
      }
    },
  });
  const projects = projectsQuery.data ?? [];
  // Failed with nothing to show (first load) vs. a failed refetch while the
  // previous rows are still on screen.
  const loadFailed = projectsQuery.isError && projectsQuery.data === undefined;
  const refetchFailed = projectsQuery.isError && projectsQuery.data !== undefined;
  const retry = () => void projectsQuery.refetch();

  // Create / delete patch the cached list in place (no refetch), exactly as
  // the previous local-state version did.
  function setProjects(update: (prev: Project[]) => Project[]) {
    queryClient.setQueryData<Project[]>(queryKeys.projects.list(), (prev) => update(prev ?? []));
  }

  async function handleCreate() {
    setCreateError(null);
    try {
      const project = await api.projects.create({ name, description });
      setProjects((prev) => [project, ...prev]);
      setDialogOpen(false);
      setName("");
      setDescription("");
    } catch (error) {
      console.error("Failed to create project:", error);
      // Keep the dialog open with the API's own reason (e.g. a validation
      // 400) — it used to close nothing and say nothing.
      setCreateError(
        error instanceof APIError && typeof error.body?.error === "string"
          ? `${t("createFailed")}: ${error.body.error}`
          : t("createFailed"),
      );
    }
  }

  function handleDialogOpenChange(open: boolean) {
    setDialogOpen(open);
    if (!open) setCreateError(null);
  }

  async function handleDelete(id: string) {
    if (!confirm(t("deleteConfirm"))) return;
    try {
      await api.projects.delete(id);
      setProjects((prev) => prev.filter((p) => p.id !== id));
    } catch (error) {
      console.error("Failed to delete project:", error);
    }
  }

  if (projectsQuery.isPending) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted-foreground">{tc("loading")}</div>
      </div>
    );
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold">{t("title")}</h1>
        <Button onClick={() => setDialogOpen(true)}>
          <Plus className="h-4 w-4 mr-2" />
          {t("create")}
        </Button>
      </div>

      {refetchFailed && (
        <LoadError
          compact
          testId="projects-load-error"
          message={t("loadFailed")}
          retryLabel={tc("retry")}
          onRetry={retry}
          retrying={projectsQuery.isFetching}
        />
      )}

      {loadFailed ? (
        <LoadError
          testId="projects-load-error"
          message={t("loadFailed")}
          retryLabel={tc("retry")}
          onRetry={retry}
          retrying={projectsQuery.isFetching}
        />
      ) : projects.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <FolderOpen className="h-12 w-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground mb-4">{t("noProjects")}</p>
            <Button onClick={() => setDialogOpen(true)}>
              <Plus className="h-4 w-4 mr-2" />
              {t("create")}
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {projects.map((project) => (
            <Card key={project.id} className="hover:shadow-md transition-shadow">
              <CardHeader className="pb-2">
                <CardTitle className="text-lg">
                  <Link href={`/projects/${project.id}`} className="hover:underline">
                    {project.name}
                  </Link>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4 line-clamp-2">
                  {project.description || t("noDescription")}
                </p>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted-foreground">
                    {new Date(project.created_at).toLocaleDateString()}
                  </span>
                  <div className="flex gap-2">
                    <Link href={`/projects/${project.id}`}>
                      <Button variant="outline" size="sm">
                        <Upload className="h-4 w-4" />
                      </Button>
                    </Link>
                    <Button
                      variant="destructive"
                      size="sm"
                      aria-label={t("deleteAriaLabel", { name: project.name })}
                      onClick={() => handleDelete(project.id)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Dialog open={dialogOpen} onOpenChange={handleDialogOpenChange}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("create")}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1">{t("name")}</label>
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={t("namePlaceholder")}
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">{t("description")}</label>
              <Input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder={t("descriptionPlaceholder")}
              />
            </div>
            {createError && (
              <p role="alert" className="text-sm text-destructive bg-destructive/10 p-3 rounded-md">
                {createError}
              </p>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => handleDialogOpenChange(false)}>
              {tc("cancel")}
            </Button>
            <Button onClick={handleCreate} disabled={!name}>
              {tc("create")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
